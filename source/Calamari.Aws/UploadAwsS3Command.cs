﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Amazon.IdentityManagement;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SecurityToken;
using Calamari.Aws.Deployment;
using Calamari.Aws.Deployment.Conventions;
using Calamari.Aws.Exceptions;
using Calamari.Aws.Integration.S3;
using Calamari.Aws.Util;
using Calamari.Commands.Support;
using Calamari.Common.Variables;
using Calamari.Deployment;
using Calamari.Deployment.Conventions;
using Calamari.Integration.FileSystem;
using Calamari.Util;
using Octopus.CoreUtilities;
using Octopus.CoreUtilities.Extensions;

namespace Calamari.Aws
{
    [Command("upload-aws-s3", Description = "Uploads a package or package file(s) to an AWS s3 bucket")]
    public class UploadAwsS3Command : AwsCommand
    {
        readonly IAmazonS3 amazonS3Client;
        readonly IProvideS3TargetOptions optionsProvider;
        readonly ICalamariFileSystem fileSystem;
        readonly ISubstituteInFiles substituteInFiles;
        readonly IExtractPackage extractPackage;
        readonly string bucketName;
        readonly S3TargetMode s3TargetMode;
        readonly bool isMd5HashSupported;

        static readonly HashSet<S3CannedACL> S3CannedAcls = new HashSet<S3CannedACL>(ConstantHelpers.GetConstantValues<S3CannedACL>());

        public UploadAwsS3Command(
            ILog log,
            IVariables variables,
            IAmazonS3 amazonS3Client,
            IAmazonSecurityTokenService amazonSecurityTokenService,
            IAmazonIdentityManagementService amazonIdentityManagementService,
            IProvideS3TargetOptions optionsProvider,
            ICalamariFileSystem fileSystem,
            ISubstituteInFiles substituteInFiles,
            IExtractPackage extractPackage) : base(log, variables, amazonSecurityTokenService, amazonIdentityManagementService)
        {
            this.amazonS3Client = amazonS3Client;
            this.optionsProvider = optionsProvider;
            this.fileSystem = fileSystem;
            this.substituteInFiles = substituteInFiles;
            this.extractPackage = extractPackage;

            bucketName = variables.Get("bucket")?.Trim();
            s3TargetMode = GetS3TargetMode(variables.Get("targetMode"));
            isMd5HashSupported = HashCalculator.IsAvailableHashingAlgorithm(MD5.Create);
        }


        //TODO: Further refactor is necessary if we have the capacity
        protected override void Execute(RunningDeployment deployment)
        {
            if (!fileSystem.FileExists(pathToPackage))
                throw new CommandException("Could not find package file: " + pathToPackage);

            Guard.NotNullOrWhiteSpace(bucketName, "Bucket name should not be null or empty");

            if (s3TargetMode == S3TargetMode.FileSelections)
            {
                extractPackage.ExtractToStagingDirectory(pathToPackage);
            }

            EnsureS3BucketExists().GetAwaiter().GetResult();
            UploadToS3Async(deployment).GetAwaiter().GetResult();
        }

        async Task EnsureS3BucketExists()
        {
            if (await Amazon.S3.Util.AmazonS3Util.DoesS3BucketExistV2Async(amazonS3Client, bucketName))
            {
                Log.Verbose($"Bucket {bucketName} exists in region {amazonS3Client.Config.RegionEndpoint}. Skipping creation.");
                return;
            }

            Log.Info($"Creating {bucketName}.");

            await amazonS3Client.PutBucketAsync(new PutBucketRequest
            {
                BucketName = bucketName,
                UseClientRegion = true
            });
        }

        static S3TargetMode GetS3TargetMode(string value)
        {
            return Enum.TryParse<S3TargetMode>(value, out var result) ? result : S3TargetMode.EntirePackage;
        }

        static string ExceptionMessageWithFilePath(PutObjectRequest request, Exception exception)
        {
            return $"Failed to upload file {request.FilePath}. {exception.Message}";
        }

        static string InvalidArgumentExceptionMessage(PutObjectRequest request, Exception exception)
        {
            //There isn't an associated error we can check for the Canned ACL so just check it against what we can determine
            //from the values in the SDK.
            var error = $"Failed to upload {request.FilePath}. An invalid argument was provided.";
            return !S3CannedAcls.Contains(request.CannedACL) ? $"{error} This is possibly due to the value specified for the canned ACL." : error;
        }

        //Errors we care about for each upload.
        readonly Dictionary<string, Func<PutObjectRequest, Exception, string>> perFileUploadErrors = new Dictionary<string, Func<PutObjectRequest, Exception, string>>
        {
            { "RequestIsNotMultiPartContent", ExceptionMessageWithFilePath },
            { "UnexpectedContent", ExceptionMessageWithFilePath },
            { "MetadataTooLarge", ExceptionMessageWithFilePath },
            { "MaxMessageLengthExceeded", ExceptionMessageWithFilePath },
            { "KeyTooLongError", ExceptionMessageWithFilePath },
            { "SignatureDoesNotMatch", ExceptionMessageWithFilePath },
            { "InvalidStorageClass", ExceptionMessageWithFilePath },
            { "InvalidArgument",  InvalidArgumentExceptionMessage },
            { "InvalidTag", ExceptionMessageWithFilePath }
        };

        async Task UploadToS3Async(RunningDeployment deployment)
        {
            //The bucket should exist at this point
            Guard.NotNull(deployment, "deployment can not be null");

            if (!isMd5HashSupported)
            {
                Log.Info("MD5 hashes are not supported in executing environment. Files will always be uploaded.");
            }

            var options = optionsProvider.GetOptions(s3TargetMode);

            try
            {
                (await UploadAll(options, deployment)).Tee(responses =>
                {
                    SetOutputVariables(deployment, responses);
                });
            }
            catch (AmazonS3Exception exception)
            {
                if (exception.ErrorCode == "AccessDenied")
                {
                    throw new PermissionException("The AWS account used to perform the operation does not have the " +
                                                  $"the required permissions to upload to bucket {bucketName}");
                }

                throw new UnknownException(
                    $"An unrecognized {exception.ErrorCode} error was thrown while uploading to bucket {bucketName}");
            }
            catch (AmazonServiceException exception)
            {
                HandleAmazonServiceException(exception);
                throw;
            }
        }

        void SetOutputVariables(RunningDeployment deployment, IEnumerable<S3UploadResult> results)
        {
            log.SetOutputVariableButDoNotAddToVariables(PackageVariables.Output.FileName, Path.GetFileName(deployment.PackageFilePath));
            log.SetOutputVariableButDoNotAddToVariables(PackageVariables.Output.FilePath, deployment.PackageFilePath);
            foreach (var result in results)
            {
                if (!result.IsSuccess()) continue;
                log.Info($"Saving object version id to variable \"Octopus.Action[{deployment.Variables["Octopus.Action.Name"]}].Output.Files[{result.BucketKey}]\"");
                log.SetOutputVariableButDoNotAddToVariables($"Files[{result.BucketKey}]", result.Version);
            }
        }

        static void ThrowInvalidFileUpload(Exception exception, string message)
        {
            throw new AmazonFileUploadException(message, exception);
        }

        static void WarnAndIgnoreException(Exception exception, string message)
        {
            Log.Warn(message);
        }

        async Task<IEnumerable<S3UploadResult>> UploadAll(IEnumerable<S3TargetPropertiesBase> options, RunningDeployment deployment)
        {
            var result = new List<S3UploadResult>();
            foreach (var option in options)
            {
                switch (option)
                {
                    case S3PackageOptions package:
                        result.Add(await UploadUsingPackage(deployment, package));
                        break;
                    case S3SingleFileSelectionProperties selection:
                        result.Add(await UploadSingleFileSelection(deployment, selection));
                        break;
                    case S3MultiFileSelectionProperties selection:
                        result.AddRange(await UploadMultiFileSelection(deployment, selection));
                        break;
                }
            }

            return result;
        }

        /// <summary>
        /// Uploads multiple files given the globbing patterns provided by the selection properties.
        /// </summary>
        /// <param name="deployment"></param>
        /// <param name="selection"></param>
        async Task<IEnumerable<S3UploadResult>> UploadMultiFileSelection(RunningDeployment deployment, S3MultiFileSelectionProperties selection)
        {
            Guard.NotNull(deployment, "Deployment may not be null");
            Guard.NotNull(selection, "Multi file selection properties may not be null");
            var results = new List<S3UploadResult>();

            var files = new RelativeGlobber((@base, pattern) => fileSystem.EnumerateFilesWithGlob(@base, pattern), deployment.StagingDirectory).EnumerateFilesWithGlob(selection.Pattern).ToList();

            if (!files.Any())
            {
                Log.Info($"The glob pattern '{selection.Pattern}' didn't match any files. Nothing was uploaded to S3.");
                return results;
            }

            Log.Info($"Glob pattern '{selection.Pattern}' matched {files.Count} files");
            var substitutionPatterns = selection.VariableSubstitutionPatterns?.Split(new[] { "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries) ?? new string[0];

            if (substitutionPatterns.Any())
                substituteInFiles.Substitute(deployment, substitutionPatterns);

            foreach (var matchedFile in files)
            {
                var request = CreateRequest(matchedFile.FilePath, $"{selection.BucketKeyPrefix}{matchedFile.MappedRelativePath}", selection);
                LogPutObjectRequest(matchedFile.FilePath, request);

                results.Add(await HandleUploadRequest(amazonS3Client, request, WarnAndIgnoreException));
            }

            return results;
        }

        /// <summary>
        /// Uploads a single file with the given properties
        /// </summary>
        /// <param name="deployment"></param>
        /// <param name="selection"></param>
        public Task<S3UploadResult> UploadSingleFileSelection(RunningDeployment deployment, S3SingleFileSelectionProperties selection)
        {
            Guard.NotNull(deployment, "Deployment may not be null");
            Guard.NotNull(selection, "Single file selection properties may not be null");

            var filePath = Path.Combine(deployment.StagingDirectory, selection.Path);

            if (!fileSystem.FileExists(filePath))
            {
                throw new FileNotFoundException($"The file {selection.Path} could not be found in the package.");
            }

            if (selection.PerformVariableSubstitution)
                substituteInFiles.Substitute(deployment, new List<string> { filePath });

            return CreateRequest(filePath, GetBucketKey(filePath.AsRelativePathFrom(deployment.StagingDirectory), selection), selection)
                    .Tee(x => LogPutObjectRequest(filePath, x))
                    .Map(x => HandleUploadRequest(amazonS3Client, x, ThrowInvalidFileUpload));
        }

        /// <summary>
        /// Uploads the given package file with the provided package options
        /// </summary>
        /// <param name="deployment"></param>
        /// <param name="options"></param>
        public Task<S3UploadResult> UploadUsingPackage(RunningDeployment deployment, S3PackageOptions options)
        {
            Guard.NotNull(deployment, "Deployment may not be null");
            Guard.NotNull(options, "Package options may not be null");

            var filename = GetNormalizedPackageFilename(deployment);

            return CreateRequest(deployment.PackageFilePath,
                    GetBucketKey(filename, options), options)
                .Tee(x => LogPutObjectRequest("entire package", x))
                .Map(x => HandleUploadRequest(amazonS3Client, x, ThrowInvalidFileUpload));
        }

        public string GetNormalizedPackageFilename(RunningDeployment deployment)
        {
            var id = deployment.Variables.Get(PackageVariables.IndexedPackageId(null));
            var version = deployment.Variables.Get(PackageVariables.IndexedPackageVersion(null));
            var extension = Path.GetExtension(deployment.Variables.Get(PackageVariables.IndexedOriginalPath(null)));
            return $"{id}.{version}{extension}";
        }

        /// <summary>
        /// Creates an upload file request based on the s3 target properties for a given file and bucket key. 
        /// </summary>
        /// <param name="path"></param>
        /// <param name="bucketKey"></param>
        /// <param name="properties"></param>
        /// <returns>PutObjectRequest with all information including metadata and tags from provided properties</returns>
        PutObjectRequest CreateRequest(string path, string bucketKey, S3TargetPropertiesBase properties)
        {
            Guard.NotNullOrWhiteSpace(path, "The given path may not be null");
            Guard.NotNullOrWhiteSpace(bucketName, "The provided bucket key may not be null");
            Guard.NotNull(properties, "Target properties may not be null");

            var request = new PutObjectRequest
            {
                FilePath = path,
                BucketName = bucketName,
                Key = bucketKey?.Trim(),
                StorageClass = S3StorageClass.FindValue(properties.StorageClass?.Trim()),
                CannedACL = S3CannedACL.FindValue(properties.CannedAcl?.Trim())
            }
                .WithMetadata(properties)
                .WithTags(properties);

            return isMd5HashSupported ? request.WithMd5Digest(fileSystem) : request;
        }

        public string GetBucketKey(string defaultKey, IHaveBucketKeyBehaviour behaviour)
        {
            return new BucketKeyProvider().GetBucketKey(defaultKey, behaviour);
        }

        /// <summary>
        /// Displays the current information regarding the object that will be uploaded to the user.
        /// </summary>
        /// <param name="fileOrPackageDescription"></param>
        /// <param name="request"></param>
        private static void LogPutObjectRequest(string fileOrPackageDescription, PutObjectRequest request)
        {
            Log.Info($"Attempting to upload {fileOrPackageDescription} to bucket {request.BucketName} with key {request.Key}.");
        }

        /// <summary>
        /// Handle the file upload request throwing exceptions only on errors from AWS which is critical enough to fail
        /// the entire deployment i.e. access denied while per file errors will result in warnings.
        /// </summary>
        /// <param name="client">The client to use</param>
        /// <param name="request">The request to send</param>
        /// <param name="errorAction">Action to take on per file error</param>
        async Task<S3UploadResult> HandleUploadRequest(IAmazonS3 client, PutObjectRequest request, Action<AmazonS3Exception, string> errorAction)
        {
            try
            {
                if (!await ShouldUpload(client, request))
                {
                    Log.Verbose(
                        $"Object key {request.Key} exists for bucket {request.BucketName} with same content hash and metadata. Skipping upload.");
                    return new S3UploadResult(request, Maybe<PutObjectResponse>.None);
                }

                return new S3UploadResult(request, Maybe<PutObjectResponse>.Some(await client.PutObjectAsync(request)));
            }
            catch (AmazonS3Exception ex)
            {
                var permissions = new List<string> { "s3:PutObject" };
                if (request.TagSet.Count > 0)
                {
                    permissions.Add("s3:PutObjectTagging");
                    permissions.Add("s3:PutObjectVersionTagging");
                }

                if (ex.ErrorCode == "AccessDenied")
                    throw new PermissionException(
                        "The AWS account used to perform the operation does not have the required permissions to upload to the bucket.\n" +
                        $"Please ensure the current account has permission to perform action(s) {string.Join(", ", permissions)}'.\n" +
                        ex.Message + "\n");

                if (!perFileUploadErrors.ContainsKey(ex.ErrorCode)) throw;
                perFileUploadErrors[ex.ErrorCode](request, ex).Tee((message) => errorAction(ex, message));
                return new S3UploadResult(request, Maybe<PutObjectResponse>.None);
            }
            catch (ArgumentException exception)
            {
                throw new AmazonFileUploadException($"An error occurred uploading file with bucket key {request.Key} possibly due to metadata. Metadata keys must be valid HTTP header values. \n" +
                                                    "Metadata:\n" + request.Metadata.Keys.Aggregate(string.Empty, (values, key) => $"{values}'{key}' = '{request.Metadata[key]}'\n") + "\n" +
                                                    $"Please see the {log.FormatLink("https://g.octopushq.com/AwsS3UsingMetadata", "AWS documentation")} for more information."
                    , exception);
            }
        }

        /// <summary>
        /// Check whether the object key exists and hash is equivalent. If these are the same we will skip the upload.
        /// </summary>
        /// <param name="client"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        async Task<bool> ShouldUpload(IAmazonS3 client, PutObjectRequest request)
        {
            //This isn't ideal, however the AWS SDK doesn't really provide any means to check the existence of an object.
            try
            {
                if (!isMd5HashSupported)
                    return true;

                var metadataResponse = await client.GetObjectMetadataAsync(request.BucketName, request.Key);
                return !metadataResponse.GetEtag().IsSameAsRequestMd5Digest(request) || !request.HasSameMetadata(metadataResponse);
            }
            catch (AmazonServiceException exception)
            {
                if (exception.StatusCode == HttpStatusCode.NotFound)
                {
                    return true;
                }

                throw;
            }
        }

        /// <summary>
        /// The AmazonServiceException can hold additional information that is useful to include in
        /// the log.
        /// </summary>
        /// <param name="exception">The exception</param>
        static void HandleAmazonServiceException(AmazonServiceException exception)
        {
            ((exception.InnerException as WebException)?
             .Response?
             .GetResponseStream()?
             .Map(stream => new StreamReader(stream).ReadToEnd())
             .Map(message => "An exception was thrown while contacting the AWS API.\n" + message)
             ?? "An exception was thrown while contacting the AWS API.")
                .Tee(Log.Warn);
        }
    }
}
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Calamari.Commands.Support;
using Calamari.Deployment;
using Octopus.CoreUtilities.Extensions;

namespace Calamari.Aws
{
    public abstract class AwsCommand : ICommand
    {
        static readonly Regex ArnNameRe = new Regex("^.*?/(.+)$");

        protected readonly ILog log;
        protected readonly IVariables variables;

        readonly IAmazonSecurityTokenService amazonSecurityTokenService;
        readonly IAmazonIdentityManagementService amazonIdentityManagementService;

        protected readonly PathToPackage pathToPackage;

        protected AwsCommand(
            ILog log,
            IVariables variables,
            IAmazonSecurityTokenService amazonSecurityTokenService,
            IAmazonIdentityManagementService amazonIdentityManagementService)
        {
            this.log = log;
            this.variables = variables;
            this.amazonSecurityTokenService = amazonSecurityTokenService;
            this.amazonIdentityManagementService = amazonIdentityManagementService;

            pathToPackage = new PathToPackage(Path.GetFullPath(variables.Get("package")));
        }

        public int Execute()
        {
            var deployment = new RunningDeployment(pathToPackage, variables);

            LogAwsUserInfoForDeployment(deployment).ConfigureAwait(false).GetAwaiter().GetResult();

            Execute(deployment);

            return 0;
        }

        protected abstract void Execute(RunningDeployment deployment);

        async Task LogAwsUserInfoForDeployment(RunningDeployment deployment)
        {
            if (deployment.Variables.IsSet(SpecialVariables.Action.Aws.AssumeRoleARN) ||
                !deployment.Variables.IsSet(SpecialVariables.Action.Aws.AccountId) ||
                !deployment.Variables.IsSet(deployment.Variables.Get(SpecialVariables.Action.Aws.AccountId) +
                                            ".AccessKey"))
            {
                await TryLogAwsUserRole();
            }
            else
            {
                await TryLogAwsUserName();
            }
        }

        async Task TryLogAwsUserName()
        {
            try
            {
                var result = await amazonIdentityManagementService.GetUserAsync(new GetUserRequest());

                log.Info($"Running the step as the AWS user {result.User.UserName}");
            }
            catch (AmazonServiceException)
            {
                // Ignore, we just won't add this to the logs
            }
        }

        async Task TryLogAwsUserRole()
        {
            try
            {
                (await amazonSecurityTokenService.GetCallerIdentityAsync(new GetCallerIdentityRequest()))
                    // The response is narrowed to the Aen
                    .Map(response => response.Arn)
                    // Try and match the response to get just the role
                    .Map(arn => ArnNameRe.Match(arn))
                    // Extract the role name, or a default
                    .Map(match => match.Success ? match.Groups[1].Value : "Unknown")
                    // Log the output
                    .Tee(role => log.Info($"Running the step as the AWS role {role}"));
            }
            catch (AmazonServiceException)
            {
                // Ignore, we just won't add this to the logs
            }
        }
    }
}
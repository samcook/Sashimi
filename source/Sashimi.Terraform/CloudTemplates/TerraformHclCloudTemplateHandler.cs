﻿using System;
using System.Collections.Generic;
using System.Linq;
using Octopus.CoreParsers.Hcl;
using Octopus.CoreUtilities.Extensions;
using Octopus.Server.Extensibility.Metadata;
using Sashimi.Server.Contracts.CloudTemplates;
using Sprache;

namespace Sashimi.Terraform.CloudTemplates
{
    public class TerraformHclCloudTemplateHandler : ICloudTemplateHandler
    {
        public bool CanHandleTemplate(string providerId, string template)
            => TerraformConstants.CloudTemplateProviderId.Equals(providerId, StringComparison.OrdinalIgnoreCase) &&
                HclFormatIdentifier.IsHcl(template);

        public Metadata ParseTypes(string template)
        {
            return template?
                .Map(GetVariables)
                .Map(variable => variable.Select(p => new PropertyMetadata
                    {
                        DisplayInfo = new DisplayInfo
                        {
                            Description = GetDefaultDescription(p),
                            Label = p.Value,
                            Required = true,
                        },
                        Type = GetType(p),
                        Name = p.Value,
                    }).ToList()
                )
                .Map(properties => new List<TypeMetadata>
                {
                    new TypeMetadata
                    {
                        Name = TerraformDataTypes.TerraformTemplateTypeName,
                        Properties = properties
                    }
                })
                .Map(typeMetadata => new Metadata() {Types = typeMetadata}) ?? new Metadata();
        }

        public object ParseModel(string template)
        {
            var parameters = GetVariables(template);
            return parameters?
                .Select(x => new KeyValuePair<string, object?>(
                    x.Value, 
                    GetDefaultValue(x))
                )
                .ToDictionary(x => x.Key, x => x.Value) ?? new Dictionary<string, object?>();
        }

        string? GetDefaultValue(HclElement argValue)
        {
            return argValue.Children?.FirstOrDefault(child => child.Name == "default")?.ToString(true, 0);
        }
        
        string? GetDefaultDescription(HclElement argValue)
        {
            return argValue.Children?.FirstOrDefault(child => child.Name == "description")?.Value;
        }

        /// <summary>
        /// https://www.terraform.io/docs/configuration/variables.html
        /// Valid values are string, list, and map. If this field is omitted, the variable type will be inferred based on default.
        /// If no default is provided, the type is assumed to be string.
        /// </summary>
        string GetType(HclElement token)
        {
            var type = token.Children?.FirstOrDefault(child => child.Name == "type");
            if (type != null)
            {
                return TerraformDataTypes.MapToType(type.Value);
            }

            // We can determine the type from the default value
            var defaultValue = token.Children?.FirstOrDefault(child => child.Name == "default");
            if (defaultValue == null) return "string";
            
            switch (defaultValue.Type)
            {
                case HclElement.ListType:
                case HclElement.ListPropertyType:
                    return TerraformDataTypes.RawList;
                case HclElement.MapType:
                case HclElement.MapPropertyType:
                    return TerraformDataTypes.RawMap;
            }

            // Otherwise we default to a string
            return "string";            
        }

        IList<HclElement> GetVariables(string template)
        {
            return template?
                .Map(HclParser.NormalizeLineEndings)
                .Map(normalized => HclParser.HclTemplate.Parse(normalized))
                .Children
                .Where(child => child.Name == "variable")
                .ToList() ?? new List<HclElement>();
        }
    }
}
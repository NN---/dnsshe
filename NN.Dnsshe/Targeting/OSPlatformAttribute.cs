// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
// ReSharper disable IdentifierTypo
// ReSharper disable CheckNamespace

namespace System.Runtime.Versioning
{
    /// <summary>
    /// Base type for all platform-specific API attributes.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    internal abstract class OSPlatformAttribute : Attribute
    {
        protected private OSPlatformAttribute(string platformName)
        {
            PlatformName = platformName;
        }
        public string PlatformName { get; }
    }
}

using System.Diagnostics.CodeAnalysis;

using NUnit.Framework;
// ReSharper disable UnusedMember.Global

// Parameter must have a non-null value when exiting.
#pragma warning disable CS8777

namespace NN.Dnsshe.Tests
{
    internal class NAssert
    {
        public static void NotNull(
            [NotNull] object? anObject,
            string? message,
            params object?[]? args)
        {
            Assert.NotNull(anObject, message, args);
        }

        public static void NotNull([NotNull] object? anObject)
        {
            Assert.NotNull(anObject);
        }
    }
}

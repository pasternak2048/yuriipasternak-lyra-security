using LYRA.Security.Enums;

namespace LYRA.Security.Signature
{
    /// <summary>
    /// Builds a canonical string to sign for requests in the <c>Cache</c> access context.
    /// Used for verifying or generating signatures for cache operations.
    /// </summary>
    public class CacheSignatureStringBuilder : ISignatureStringBuilder
    {
        /// <summary>
        /// Gets the access context associated with this builder, which is <c>Cache</c>.
        /// </summary>
        public AccessContext Context => AccessContext.Cache;

        /// <summary>
        /// Builds the canonical string used for signature generation or verification for cache operations.
        /// </summary>
        /// <param name="caller">The system name of the initiating touchpoint.</param>
        /// <param name="target">The system name of the receiving touchpoint.</param>
        /// <param name="method">Cache operation (e.g., GET, SET).</param>
        /// <param name="path">Cache key (e.g., "user:123").</param>
        /// <param name="payloadHash">Base64-encoded SHA-512 hash of the payload content.</param>
        /// <param name="timestamp">UTC timestamp when the signature is generated.</param>
        /// <returns>A canonical string to be signed.</returns>
        public string BuildStringToSign(
            string caller,
            string target,
            string method,
            string path,
            string payloadHash,
            string timestamp)
        {
            return string.Join("&", new[]
            {
                $"caller={caller}",
                $"target={target}",
                $"operation={method}",
                $"key={path}",
                $"payloadHash={payloadHash}",
                $"timestamp={timestamp}",
                $"context={Context}"
            });
        }
    }
}

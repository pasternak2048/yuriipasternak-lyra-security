using LYRA.Security.Enums;

namespace LYRA.Security.Signature
{
    /// <summary>
    /// Builds a canonical string to sign for requests in the <c>Http</c> access context.
    /// Used for verifying or generating signatures for HTTP-based inter-service communication.
    /// </summary>
    public class HttpSignatureStringBuilder : ISignatureStringBuilder
    {
        /// <summary>
        /// Gets the access context associated with this builder, which is <c>Http</c>.
        /// </summary>
        public AccessContext Context => AccessContext.Http;

        /// <summary>
        /// Builds the canonical string used for signature generation or verification for HTTP requests.
        /// </summary>
        /// <param name="caller">The system name of the initiating touchpoint.</param>
        /// <param name="target">The system name of the receiving touchpoint.</param>
        /// <param name="method">The logical action or HTTP method (e.g., POST, GET).</param>
        /// <param name="path">The path or topic (e.g., /api/orders, event.created).</param>
        /// <param name="payloadHash">Base64-encoded SHA-512 hash of the payload content.</param>
        /// <param name="timestamp">UTC timestamp when the signature is generated.</param>
        /// <returns>A canonical string used for signing or verifying the request.</returns>
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
                $"method={method}",
                $"path={path}",
                $"payloadHash={payloadHash}",
                $"timestamp={timestamp}",
                $"context={Context}"
            });
        }
    }
}

using LYRA.Security.Enums;
using LYRA.Security.Models.Verify;

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
        /// <param name="request">The request containing relevant cache operation data.</param>
        /// <returns>A string representing the canonical form of the request for signature purposes.</returns>
        public string BuildStringToSign(VerifyRequest request)
        {
            return $"caller={request.Caller}&target={request.Target}&operation={request.Method}&key={request.Path}&payloadHash={request.PayloadHash}&timestamp={request.Timestamp}";
        }
    }
}

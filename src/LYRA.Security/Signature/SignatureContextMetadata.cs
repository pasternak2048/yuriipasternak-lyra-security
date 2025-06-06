using LYRA.Security.Enums;
using LYRA.Security.Models.Verify;

namespace LYRA.Security.Signature
{
    /// <summary>
    /// Metadata for an access context signature rule, such as whether payload hash verification is required.
    /// </summary>
    public class SignatureContextMetadata
    {
        /// <summary>
        /// The access context this metadata applies to.
        /// </summary>
        public AccessContext Context { get; set; }

        /// <summary>
        /// Function that determines if a payload hash is required for a given request.
        /// </summary>
        public Func<VerifyRequest, bool> RequiresPayloadHash { get; set; } = _ => false;
    }
}

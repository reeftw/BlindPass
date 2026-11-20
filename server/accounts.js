import { createHash } from 'node:crypto';

const OAUTH_PROVIDERS = new Set(['google', 'microsoft']);

export function hashOAuthSubject(provider, subject) {
    if (!OAUTH_PROVIDERS.has(provider) || typeof subject !== 'string' || !subject) {
        throw new Error('A supported OAuth provider and subject are required');
    }
    return createHash('sha256')
        .update(`${provider}:${subject}`, 'utf8')
        .digest('hex');
}

export async function resolveOAuthUser(supabase, provider, subject) {
    const oauthSubjectHash = hashOAuthSubject(provider, subject);
    const { data: existingUser, error: lookupError } = await supabase
        .from('users')
        .select('id')
        .eq('oauth_subject_hash', oauthSubjectHash)
        .maybeSingle();

    if (lookupError) throw lookupError;
    if (existingUser) return existingUser.id;

    const { data: createdUser, error: insertError } = await supabase
        .from('users')
        .insert({
            oauth_provider: provider,
            oauth_subject_hash: oauthSubjectHash,
        })
        .select('id')
        .single();

    if (!insertError) return createdUser.id;
    if (insertError.code !== '23505') throw insertError;

    const { data: racedUser, error: racedLookupError } = await supabase
        .from('users')
        .select('id')
        .eq('oauth_subject_hash', oauthSubjectHash)
        .single();
    if (racedLookupError) throw racedLookupError;
    return racedUser.id;
}

export async function resolvePasskeyCredential(supabase, credentialId) {
    const { data, error } = await supabase
        .from('passkeys')
        .select('id, user_id, credential_id, public_key, counter, transports')
        .eq('credential_id', credentialId)
        .maybeSingle();
    if (error) throw error;
    return data;
}

import { createHash, createHmac } from 'node:crypto';

const OAUTH_PROVIDERS = new Set(['google', 'microsoft']);

export function hashOAuthSubject(
    provider,
    subject,
    pepper = process.env.OAUTH_SUBJECT_PEPPER || process.env.SESSION_SECRET
) {
    if (
        !OAUTH_PROVIDERS.has(provider) ||
        typeof subject !== 'string' ||
        !subject ||
        typeof pepper !== 'string' ||
        pepper.length < 32
    ) {
        throw new Error('A supported OAuth provider and subject are required');
    }
    return createHmac('sha256', pepper)
        .update(`${provider}:${subject}`, 'utf8')
        .digest('hex');
}

export async function resolveOAuthUser(supabase, provider, subject, pepper) {
    const oauthSubjectHash = hashOAuthSubject(provider, subject, pepper);
    const { data: existingUser, error: lookupError } = await supabase
        .from('users')
        .select('id')
        .eq('oauth_subject_hash', oauthSubjectHash)
        .maybeSingle();

    if (lookupError) throw lookupError;
    if (existingUser) return existingUser.id;

    // Rotate legacy unkeyed identifiers on successful sign-in without retaining the subject.
    const legacyHash = createHash('sha256')
        .update(`${provider}:${subject}`, 'utf8')
        .digest('hex');
    const { data: legacyUser, error: legacyLookupError } = await supabase
        .from('users')
        .select('id')
        .eq('oauth_subject_hash', legacyHash)
        .maybeSingle();
    if (legacyLookupError) throw legacyLookupError;
    if (legacyUser) {
        const { data: migratedUser, error: migrationError } = await supabase
            .from('users')
            .update({ oauth_subject_hash: oauthSubjectHash })
            .eq('id', legacyUser.id)
            .select('id')
            .maybeSingle();
        if (!migrationError && migratedUser) return migratedUser.id;
        if (migrationError && migrationError.code !== '23505') throw migrationError;

        const { data: racedUser, error: racedLookupError } = await supabase
            .from('users')
            .select('id')
            .eq('oauth_subject_hash', oauthSubjectHash)
            .maybeSingle();
        if (racedLookupError) throw racedLookupError;
        if (racedUser) return racedUser.id;
        if (migrationError) throw migrationError;
        throw new Error('Could not migrate the existing OAuth account identifier');
    }

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

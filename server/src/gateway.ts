// Вызов gateway-agent. Управляется флагом GW_AGENT_ENABLED.
export async function gwUpsertPeer(
  server: any,
  devicePubKey: string,
  addressCidr: string,
  rateMbps: number
) {
  const enabled = (process.env.GW_AGENT_ENABLED || 'false') === 'true';
  if (!enabled) {
    // eslint-disable-next-line no-console
    console.log('[gw-agent] disabled; would upsert peer', { server: server.name, addressCidr, rateMbps });
    return;
  }
  const url = new URL('/peers/upsert', server.apiUrl);
  const resp = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${server.apiToken}`
    },
    body: JSON.stringify({
      pubKey: devicePubKey,
      addressCidr,
      rateMbps,
      allowedIps: addressCidr
    })
  } as any);
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`gw upsert failed: ${resp.status} ${text}`);
  }
}
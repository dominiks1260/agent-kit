#!/usr/bin/env node

/**
 * KeyID MCP Server — exposes agent email tools via Model Context Protocol.
 *
 * Tools (27):
 *   keyid_provision          — Register agent and get email address
 *   keyid_get_email          — Get current active email address
 *   keyid_get_inbox          — Fetch inbox messages (with search)
 *   keyid_send               — Send email (scheduled, display name)
 *   keyid_reply              — Reply to a message
 *   keyid_forward            — Forward a message
 *   keyid_list_threads       — List conversation threads
 *   keyid_get_thread         — Get thread with messages
 *   keyid_create_draft       — Create a draft
 *   keyid_send_draft         — Send a draft
 *   keyid_list_webhooks      — List webhooks
 *   keyid_create_webhook     — Create a webhook
 *   keyid_manage_list        — Add/remove from allowlist/blocklist
 *   keyid_get_metrics        — Get email metrics
 *   keyid_update_message     — Update message flags (read/starred)
 *   keyid_get_unread_count   — Get unread message count
 *   keyid_get_auto_reply     — Get auto-reply settings
 *   keyid_set_auto_reply     — Configure auto-reply
 *   keyid_get_signature      — Get email signature
 *   keyid_set_signature      — Set email signature
 *   keyid_get_forwarding     — Get forwarding settings
 *   keyid_set_forwarding     — Configure email forwarding
 *   keyid_list_contacts      — List saved contacts
 *   keyid_create_contact     — Create a contact
 *   keyid_delete_contact     — Delete a contact
 *   keyid_get_webhook_deliveries — Get webhook delivery history
 *
 * Usage:
 *   npx @keyid/agent-kit
 */

const crypto = require('crypto');
const readline = require('readline');

const BASE_URL = process.env.KEYID_BASE_URL || 'https://keyid.ai';

// -- Ed25519 helpers ------------------------------------------
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex'),
  };
}

function signMessage(message, privateKeyHex) {
  const privDer = Buffer.concat([PKCS8_PREFIX, Buffer.from(privateKeyHex, 'hex')]);
  const key = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(message), key).toString('hex');
}

// -- State ----------------------------------------------------
let keypair = null;
let token = null;
let tokenExpiresAt = 0;

function getKeypair() {
  if (!keypair) {
    const pubEnv = process.env.KEYID_PUBLIC_KEY;
    const privEnv = process.env.KEYID_PRIVATE_KEY;
    if (pubEnv && privEnv) {
      keypair = { publicKey: pubEnv, privateKey: privEnv };
    } else {
      keypair = generateKeypair();
    }
  }
  return keypair;
}

async function apiFetch(path, options = {}) {
  const url = BASE_URL.replace(/\/$/, '') + path;
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  const res = await fetch(url, { ...options, headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function ensureAuth() {
  if (token && Date.now() < tokenExpiresAt - 60_000) return;
  const kp = getKeypair();
  const { nonce } = await apiFetch('/api/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ pubkey: kp.publicKey }),
  });
  const signature = signMessage(nonce, kp.privateKey);
  const result = await apiFetch('/api/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ pubkey: kp.publicKey, nonce, signature }),
  });
  token = result.token;
  tokenExpiresAt = new Date(result.expiresAt).getTime();
}

function authHeaders() {
  return { Authorization: `Bearer ${token}` };
}

// -- Tool definitions -----------------------------------------
const TOOLS = [
  {
    name: 'keyid_provision',
    description: 'Register this agent with KeyID and get an email address. Call this first before using other KeyID tools.',
    inputSchema: {
      type: 'object',
      properties: {
        storage_type: {
          type: 'string',
          enum: ['filesystem', 'env', 'memory', 'secrets_manager', 'stateless'],
          description: 'How this agent persists its private key',
        },
      },
    },
  },
  {
    name: 'keyid_get_email',
    description: 'Get the current active email address assigned to this agent.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'keyid_get_inbox',
    description: 'Fetch inbox messages. Returns messages across all current and historical email addresses. Supports full-text search.',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'number', description: 'Page number (default 1)' },
        limit: { type: 'number', description: 'Messages per page (default 50, max 100)' },
        direction: { type: 'string', enum: ['inbound', 'outbound'], description: 'Filter by direction' },
        labels: { type: 'string', description: 'Comma-separated label filter' },
        search: { type: 'string', description: 'Full-text search query (searches subject, body, addresses)' },
      },
    },
  },
  {
    name: 'keyid_send',
    description: 'Send an email from this agent. Supports HTML, CC, BCC, attachments, display name, and scheduled delivery.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient email address' },
        subject: { type: 'string', description: 'Email subject' },
        body: { type: 'string', description: 'Plain text body' },
        html: { type: 'string', description: 'HTML body (optional)' },
        cc: { type: 'array', items: { type: 'string' }, description: 'CC recipients' },
        bcc: { type: 'array', items: { type: 'string' }, description: 'BCC recipients' },
        thread_id: { type: 'string', description: 'Thread ID to add message to' },
        display_name: { type: 'string', description: 'Sender display name (optional)' },
        scheduled_at: { type: 'string', description: 'ISO 8601 date to schedule delivery (must be in the future)' },
      },
      required: ['to', 'subject', 'body'],
    },
  },
  {
    name: 'keyid_reply',
    description: 'Reply to a message. Automatically sets subject, thread, and in-reply-to headers.',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string', description: 'ID of the message to reply to' },
        body: { type: 'string', description: 'Reply body text' },
        html: { type: 'string', description: 'HTML body (optional)' },
        reply_all: { type: 'boolean', description: 'Reply to all recipients (default false)' },
      },
      required: ['message_id', 'body'],
    },
  },
  {
    name: 'keyid_forward',
    description: 'Forward a message to another recipient.',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string', description: 'ID of the message to forward' },
        to: { type: 'string', description: 'Forward recipient email' },
        body: { type: 'string', description: 'Additional message text (optional)' },
      },
      required: ['message_id', 'to'],
    },
  },
  {
    name: 'keyid_list_threads',
    description: 'List conversation threads with filtering and pagination.',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'number', description: 'Page number (default 1)' },
        limit: { type: 'number', description: 'Threads per page (default 50)' },
        labels: { type: 'string', description: 'Comma-separated label filter' },
      },
    },
  },
  {
    name: 'keyid_get_thread',
    description: 'Get a thread with all its messages.',
    inputSchema: {
      type: 'object',
      properties: {
        thread_id: { type: 'string', description: 'Thread ID' },
      },
      required: ['thread_id'],
    },
  },
  {
    name: 'keyid_create_draft',
    description: 'Create a draft email for later editing and sending.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient' },
        subject: { type: 'string', description: 'Subject' },
        body: { type: 'string', description: 'Plain text body' },
        html_body: { type: 'string', description: 'HTML body' },
        cc: { type: 'array', items: { type: 'string' }, description: 'CC recipients' },
        bcc: { type: 'array', items: { type: 'string' }, description: 'BCC recipients' },
      },
    },
  },
  {
    name: 'keyid_send_draft',
    description: 'Send a previously created draft.',
    inputSchema: {
      type: 'object',
      properties: {
        draft_id: { type: 'string', description: 'Draft ID to send' },
      },
      required: ['draft_id'],
    },
  },
  {
    name: 'keyid_list_webhooks',
    description: 'List all configured webhooks.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'keyid_create_webhook',
    description: 'Create a webhook to receive event notifications.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Webhook URL' },
        events: {
          type: 'array', items: { type: 'string' },
          description: 'Events to subscribe to: message.received, message.sent, message.delivered, message.bounced, message.complained, message.rejected, domain.verified',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'keyid_manage_list',
    description: 'Add or remove entries from allowlist/blocklist for inbound/outbound filtering.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'remove', 'list'], description: 'Action to perform' },
        direction: { type: 'string', enum: ['inbound', 'outbound'], description: 'Direction' },
        type: { type: 'string', enum: ['allow', 'block'], description: 'List type' },
        entry: { type: 'string', description: 'Email or domain (required for add/remove)' },
      },
      required: ['action', 'direction', 'type'],
    },
  },
  {
    name: 'keyid_get_metrics',
    description: 'Get email metrics with time-series aggregation.',
    inputSchema: {
      type: 'object',
      properties: {
        event: { type: 'string', description: 'Event type filter (e.g. message.received)' },
        period: { type: 'string', enum: ['hour', 'day', 'week', 'month'], description: 'Aggregation period' },
        since: { type: 'string', description: 'Start date (ISO 8601)' },
        until: { type: 'string', description: 'End date (ISO 8601)' },
      },
    },
  },
  {
    name: 'keyid_update_message',
    description: 'Update message flags (read/starred status).',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string', description: 'Message ID' },
        is_read: { type: 'boolean', description: 'Mark as read/unread' },
        is_starred: { type: 'boolean', description: 'Star/unstar message' },
      },
      required: ['message_id'],
    },
  },
  {
    name: 'keyid_get_unread_count',
    description: 'Get the count of unread messages in the inbox.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'keyid_get_auto_reply',
    description: 'Get current auto-reply (vacation responder) settings.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'keyid_set_auto_reply',
    description: 'Configure auto-reply (vacation responder). Set enabled=false to disable.',
    inputSchema: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', description: 'Enable or disable auto-reply' },
        subject: { type: 'string', description: 'Auto-reply subject line' },
        body: { type: 'string', description: 'Auto-reply message body' },
        start_date: { type: 'string', description: 'Start date (ISO 8601, optional)' },
        end_date: { type: 'string', description: 'End date (ISO 8601, optional)' },
      },
      required: ['enabled'],
    },
  },
  {
    name: 'keyid_get_signature',
    description: 'Get the email signature for this agent.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'keyid_set_signature',
    description: 'Set the email signature for this agent.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Plain text signature' },
        html: { type: 'string', description: 'HTML signature (optional)' },
      },
      required: ['text'],
    },
  },
  {
    name: 'keyid_get_forwarding',
    description: 'Get email forwarding settings.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'keyid_set_forwarding',
    description: 'Configure email forwarding to another address.',
    inputSchema: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', description: 'Enable or disable forwarding' },
        address: { type: 'string', description: 'Forwarding destination email' },
        keep_copy: { type: 'boolean', description: 'Keep a copy in inbox (default true)' },
      },
      required: ['enabled'],
    },
  },
  {
    name: 'keyid_list_contacts',
    description: 'List saved contacts.',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'number', description: 'Page number (default 1)' },
        limit: { type: 'number', description: 'Contacts per page (default 50)' },
      },
    },
  },
  {
    name: 'keyid_create_contact',
    description: 'Create a new contact.',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: 'Contact email address' },
        name: { type: 'string', description: 'Contact name' },
        notes: { type: 'string', description: 'Notes about this contact' },
      },
      required: ['email'],
    },
  },
  {
    name: 'keyid_delete_contact',
    description: 'Delete a contact.',
    inputSchema: {
      type: 'object',
      properties: {
        contact_id: { type: 'string', description: 'Contact ID to delete' },
      },
      required: ['contact_id'],
    },
  },
  {
    name: 'keyid_get_webhook_deliveries',
    description: 'Get webhook delivery history with status and retry info.',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'number', description: 'Page number (default 1)' },
        limit: { type: 'number', description: 'Deliveries per page (default 50)' },
      },
    },
  },
];

// -- Tool handlers --------------------------------------------
async function handleTool(name, args) {
  const kp = getKeypair();

  switch (name) {
    case 'keyid_provision': {
      const result = await apiFetch('/api/provision', {
        method: 'POST',
        body: JSON.stringify({ pubkey: kp.publicKey, storageType: args.storage_type || 'memory' }),
      });
      return `Provisioned agent.\nEmail: ${result.email}\nAgent ID: ${result.agentId}\nClassification: ${result.classification}\n\nPublic key (save this): ${kp.publicKey}\nPrivate key (keep secret): ${kp.privateKey}`;
    }
    case 'keyid_get_email': {
      await ensureAuth();
      const identity = await apiFetch('/api/identity', { headers: authHeaders() });
      return `Current email: ${identity.email}\nDomain: ${identity.domain}\nClassification: ${identity.classification}`;
    }
    case 'keyid_get_inbox': {
      await ensureAuth();
      const params = new URLSearchParams();
      if (args.page) params.set('page', String(args.page));
      if (args.limit) params.set('limit', String(args.limit));
      if (args.direction) params.set('direction', args.direction);
      if (args.labels) params.set('labels', args.labels);
      if (args.search) params.set('search', args.search);
      const qs = params.toString();
      const inbox = await apiFetch(`/api/inbox${qs ? '?' + qs : ''}`, { headers: authHeaders() });
      if (!inbox.messages.length) return `Inbox empty. Total messages: ${inbox.total}`;
      const lines = inbox.messages.map(m =>
        `[${m.direction}] ${m.from} → ${m.to}\n  Subject: ${m.subject}\n  ${m.body?.slice(0, 200) || '(no body)'}\n  ${m.createdAt}`
      );
      return `Inbox (${inbox.total} total, page ${inbox.page}):\n\n${lines.join('\n\n')}`;
    }
    case 'keyid_send': {
      await ensureAuth();
      const payload = { to: args.to, subject: args.subject, body: args.body };
      if (args.html) payload.html = args.html;
      if (args.cc) payload.cc = args.cc;
      if (args.bcc) payload.bcc = args.bcc;
      if (args.thread_id) payload.threadId = args.thread_id;
      if (args.display_name) payload.displayName = args.display_name;
      if (args.scheduled_at) payload.scheduledAt = args.scheduled_at;
      const result = await apiFetch('/api/send', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      const status = result.status === 'scheduled' ? `Scheduled for ${result.scheduledAt}` : 'Sent';
      return `Email ${status.toLowerCase()}.\nFrom: ${result.from}\nTo: ${args.to}\nMessage ID: ${result.messageId}${result.threadId ? '\nThread: ' + result.threadId : ''}`;
    }
    case 'keyid_reply': {
      await ensureAuth();
      const endpoint = args.reply_all
        ? `/api/inbox/${args.message_id}/reply-all`
        : `/api/inbox/${args.message_id}/reply`;
      const payload = { body: args.body };
      if (args.html) payload.html = args.html;
      const result = await apiFetch(endpoint, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return `Reply sent.\nMessage ID: ${result.messageId}\nFrom: ${result.from}`;
    }
    case 'keyid_forward': {
      await ensureAuth();
      const payload = { to: args.to };
      if (args.body) payload.body = args.body;
      const result = await apiFetch(`/api/inbox/${args.message_id}/forward`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return `Message forwarded.\nTo: ${args.to}\nMessage ID: ${result.messageId}`;
    }
    case 'keyid_list_threads': {
      await ensureAuth();
      const params = new URLSearchParams();
      if (args.page) params.set('page', String(args.page));
      if (args.limit) params.set('limit', String(args.limit));
      if (args.labels) params.set('labels', args.labels);
      const qs = params.toString();
      const data = await apiFetch(`/api/threads${qs ? '?' + qs : ''}`, { headers: authHeaders() });
      if (!data.threads.length) return `No threads found. Total: ${data.total}`;
      const lines = data.threads.map(t =>
        `[${t.id}] ${t.subject || '(no subject)'} — ${t.messageCount} messages, last: ${t.lastMessageAt}`
      );
      return `Threads (${data.total} total, page ${data.page}):\n\n${lines.join('\n')}`;
    }
    case 'keyid_get_thread': {
      await ensureAuth();
      const thread = await apiFetch(`/api/threads/${args.thread_id}`, { headers: authHeaders() });
      const msgs = (thread.messages || []).map(m =>
        `  [${m.direction}] ${m.from} → ${m.to}\n    ${m.subject}\n    ${m.body?.slice(0, 200) || '(no body)'}\n    ${m.createdAt}`
      );
      return `Thread: ${thread.subject || '(no subject)'}\nMessages (${thread.messageCount}):\n\n${msgs.join('\n\n')}`;
    }
    case 'keyid_create_draft': {
      await ensureAuth();
      const payload = {};
      if (args.to) payload.to = args.to;
      if (args.subject) payload.subject = args.subject;
      if (args.body) payload.body = args.body;
      if (args.html_body) payload.htmlBody = args.html_body;
      if (args.cc) payload.cc = args.cc;
      if (args.bcc) payload.bcc = args.bcc;
      const result = await apiFetch('/api/drafts', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return `Draft created.\nDraft ID: ${result.draftId}`;
    }
    case 'keyid_send_draft': {
      await ensureAuth();
      const result = await apiFetch(`/api/drafts/${args.draft_id}/send`, {
        method: 'POST',
        headers: authHeaders(),
      });
      return `Draft sent.\nMessage ID: ${result.messageId}\nFrom: ${result.from}`;
    }
    case 'keyid_list_webhooks': {
      await ensureAuth();
      const data = await apiFetch('/api/webhooks', { headers: authHeaders() });
      if (!data.webhooks.length) return 'No webhooks configured.';
      const lines = data.webhooks.map(w =>
        `[${w.id}] ${w.url} — events: ${w.events.join(', ')} — ${w.active ? 'active' : 'inactive'}`
      );
      return `Webhooks:\n\n${lines.join('\n')}`;
    }
    case 'keyid_create_webhook': {
      await ensureAuth();
      const payload = { url: args.url };
      if (args.events) payload.events = args.events;
      const result = await apiFetch('/api/webhooks', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return `Webhook created.\nID: ${result.webhookId}\nSecret: ${result.secret}\nEvents: ${result.events.join(', ')}`;
    }
    case 'keyid_manage_list': {
      await ensureAuth();
      const { action, direction, type, entry } = args;
      if (action === 'list') {
        const data = await apiFetch(`/api/lists/${direction}/${type}`, { headers: authHeaders() });
        if (!data.entries.length) return `${direction} ${type}list is empty.`;
        return `${direction} ${type}list:\n${data.entries.map(e => `  ${e.entry} (added ${e.createdAt})`).join('\n')}`;
      }
      if (action === 'add') {
        await apiFetch(`/api/lists/${direction}/${type}`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ entry }),
        });
        return `Added "${entry}" to ${direction} ${type}list.`;
      }
      if (action === 'remove') {
        await apiFetch(`/api/lists/${direction}/${type}/${encodeURIComponent(entry)}`, {
          method: 'DELETE',
          headers: authHeaders(),
        });
        return `Removed "${entry}" from ${direction} ${type}list.`;
      }
      throw new Error(`Unknown action: ${action}`);
    }
    case 'keyid_get_metrics': {
      await ensureAuth();
      const params = new URLSearchParams();
      if (args.event) params.set('event', args.event);
      if (args.period) params.set('period', args.period);
      if (args.since) params.set('since', args.since);
      if (args.until) params.set('until', args.until);
      const qs = params.toString();
      const data = await apiFetch(`/api/metrics${qs ? '?' + qs : ''}`, { headers: authHeaders() });
      if (!data.metrics.length) return `No metrics data. Total events: ${data.total}`;
      const lines = data.metrics.map(m => `  ${m.period}: ${m.count}`);
      return `Metrics (total: ${data.total}):\n${lines.join('\n')}`;
    }
    case 'keyid_update_message': {
      await ensureAuth();
      const payload = {};
      if (args.is_read !== undefined) payload.isRead = args.is_read;
      if (args.is_starred !== undefined) payload.isStarred = args.is_starred;
      await apiFetch(`/api/inbox/${args.message_id}`, {
        method: 'PATCH',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      const flags = [];
      if (args.is_read !== undefined) flags.push(args.is_read ? 'read' : 'unread');
      if (args.is_starred !== undefined) flags.push(args.is_starred ? 'starred' : 'unstarred');
      return `Message ${args.message_id} marked as ${flags.join(', ')}.`;
    }
    case 'keyid_get_unread_count': {
      await ensureAuth();
      const data = await apiFetch('/api/inbox/unread-count', { headers: authHeaders() });
      return `Unread messages: ${data.count}`;
    }
    case 'keyid_get_auto_reply': {
      await ensureAuth();
      const data = await apiFetch('/api/settings/auto-reply', { headers: authHeaders() });
      if (!data.enabled) return 'Auto-reply is disabled.';
      return `Auto-reply: enabled\nSubject: ${data.subject || '(default)'}\nBody: ${data.body}\nStart: ${data.startDate || 'immediate'}\nEnd: ${data.endDate || 'indefinite'}`;
    }
    case 'keyid_set_auto_reply': {
      await ensureAuth();
      const payload = { enabled: args.enabled };
      if (args.subject) payload.subject = args.subject;
      if (args.body) payload.body = args.body;
      if (args.start_date) payload.startDate = args.start_date;
      if (args.end_date) payload.endDate = args.end_date;
      await apiFetch('/api/settings/auto-reply', {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return args.enabled ? 'Auto-reply enabled.' : 'Auto-reply disabled.';
    }
    case 'keyid_get_signature': {
      await ensureAuth();
      const data = await apiFetch('/api/settings/signature', { headers: authHeaders() });
      if (!data.text && !data.html) return 'No signature set.';
      return `Signature:\n${data.text}${data.html ? '\n(HTML version also set)' : ''}`;
    }
    case 'keyid_set_signature': {
      await ensureAuth();
      const payload = { text: args.text };
      if (args.html) payload.html = args.html;
      await apiFetch('/api/settings/signature', {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return 'Signature updated.';
    }
    case 'keyid_get_forwarding': {
      await ensureAuth();
      const data = await apiFetch('/api/settings/forwarding', { headers: authHeaders() });
      if (!data.enabled) return 'Forwarding is disabled.';
      return `Forwarding: enabled\nTo: ${data.address}\nKeep copy: ${data.keepCopy ? 'yes' : 'no'}`;
    }
    case 'keyid_set_forwarding': {
      await ensureAuth();
      const payload = { enabled: args.enabled };
      if (args.address) payload.address = args.address;
      if (args.keep_copy !== undefined) payload.keepCopy = args.keep_copy;
      await apiFetch('/api/settings/forwarding', {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return args.enabled ? `Forwarding enabled to ${args.address}.` : 'Forwarding disabled.';
    }
    case 'keyid_list_contacts': {
      await ensureAuth();
      const params = new URLSearchParams();
      if (args.page) params.set('page', String(args.page));
      if (args.limit) params.set('limit', String(args.limit));
      const qs = params.toString();
      const data = await apiFetch(`/api/contacts${qs ? '?' + qs : ''}`, { headers: authHeaders() });
      if (!data.contacts.length) return `No contacts. Total: ${data.total}`;
      const lines = data.contacts.map(c => `  ${c.name || '(no name)'} <${c.email}>${c.notes ? ' — ' + c.notes : ''}`);
      return `Contacts (${data.total} total):\n${lines.join('\n')}`;
    }
    case 'keyid_create_contact': {
      await ensureAuth();
      const payload = { email: args.email };
      if (args.name) payload.name = args.name;
      if (args.notes) payload.notes = args.notes;
      const result = await apiFetch('/api/contacts', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      return `Contact created.\nID: ${result.contactId}\nEmail: ${args.email}`;
    }
    case 'keyid_delete_contact': {
      await ensureAuth();
      await apiFetch(`/api/contacts/${args.contact_id}`, {
        method: 'DELETE',
        headers: authHeaders(),
      });
      return `Contact ${args.contact_id} deleted.`;
    }
    case 'keyid_get_webhook_deliveries': {
      await ensureAuth();
      const params = new URLSearchParams();
      if (args.page) params.set('page', String(args.page));
      if (args.limit) params.set('limit', String(args.limit));
      const qs = params.toString();
      const data = await apiFetch(`/api/webhooks/deliveries${qs ? '?' + qs : ''}`, { headers: authHeaders() });
      if (!data.deliveries.length) return `No webhook deliveries. Total: ${data.total}`;
      const lines = data.deliveries.map(d =>
        `  [${d.status}] ${d.event} → ${d.url} (${d.attempts} attempts)${d.error ? ' — ' + d.error : ''}`
      );
      return `Webhook deliveries (${data.total} total):\n${lines.join('\n')}`;
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// -- MCP JSON-RPC transport (stdio) ---------------------------
const rl = readline.createInterface({ input: process.stdin, terminal: false });
let buffer = '';

function sendResponse(id, result) {
  const msg = JSON.stringify({ jsonrpc: '2.0', id, result });
  process.stdout.write(`Content-Length: ${Buffer.byteLength(msg)}\r\n\r\n${msg}`);
}

function sendError(id, code, message) {
  const msg = JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } });
  process.stdout.write(`Content-Length: ${Buffer.byteLength(msg)}\r\n\r\n${msg}`);
}

rl.on('line', async (line) => {
  buffer += line;

  try {
    const request = JSON.parse(buffer);
    buffer = '';

    const { id, method, params } = request;

    switch (method) {
      case 'initialize':
        sendResponse(id, {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'keyid', version: '0.4.0' },
        });
        break;

      case 'tools/list':
        sendResponse(id, { tools: TOOLS });
        break;

      case 'tools/call': {
        try {
          const text = await handleTool(params.name, params.arguments || {});
          sendResponse(id, { content: [{ type: 'text', text }] });
        } catch (err) {
          sendResponse(id, {
            content: [{ type: 'text', text: `Error: ${err.message}` }],
            isError: true,
          });
        }
        break;
      }

      case 'notifications/initialized':
        break;

      default:
        if (id) sendError(id, -32601, `Method not found: ${method}`);
    }
  } catch {
    // Incomplete JSON, wait for more data
  }
});

process.stderr.write('[keyid-mcp] Server started\n');

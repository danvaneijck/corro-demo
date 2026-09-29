// Unified Inbox web client. Vanilla JS, no build step, served by api-fn from the API's own
// origin. Every piece of user or API data is rendered with textContent, never as HTML.
'use strict';

const DEMO_ACCOUNTS = [
  { email: 'alice@acme.test', label: 'Alice, acme admin' },
  { email: 'bob@acme.test', label: 'Bob, acme member' },
  { email: 'carol@acme.test', label: 'Carol, acme member' },
  { email: 'dave@globex.test', label: 'Dave, globex admin' },
  { email: 'ops@corro.test', label: 'Ops, platform operator' },
];
const OTHER_TENANT = { acme: 'globex', globex: 'acme' };
const FOREIGN_CONVERSATION = { acme: 'c_ward', globex: 'c_ops' };
const POLL_MS = 5000;
const MAX_CHARS = 1000;

const state = {
  config: null,
  token: null,
  me: null,
  names: new Map(), // user_id -> display name
  tab: 'inbox',
  conversations: [],
  current: null, // conversation id
  messages: [], // oldest first
  olderCursor: null,
  poll: null,
};

// ---------------------------------------------------------------- DOM helpers

/** h('div', {class: 'x', onclick: fn}, 'text', childNode, [more]) */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const app = () => document.getElementById('app');
const show = (...nodes) => app().replaceChildren(...nodes);

function time(iso) {
  const d = new Date(iso);
  const today = new Date().toDateString() === d.toDateString();
  return today
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

function channelBadge(ch) {
  const label = { slack: 'Slack', sms: 'SMS', native: 'App', email: 'Email' }[ch] || ch;
  return h('span', { class: `badge ${ch}` }, label);
}

function outcomeBadge(outcome) {
  const cls = { allowed: 'ok', duplicate: 'warn', denied: 'bad', denied_by_iam: 'bad', error: 'bad' }[outcome] || '';
  return h('span', { class: `badge ${cls}` }, outcome);
}

// ---------------------------------------------------------------- API and auth

class ApiError extends Error {
  constructor(status, body) {
    super(`HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { Authorization: `Bearer ${state.token}`, 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (res.status === 401) { signOut('Your session expired. Sign in again.'); throw new ApiError(401, body); }
  if (!res.ok) throw new ApiError(res.status, body);
  return body;
}

/** Like api(), but returns {status, body} for any status, for the isolation panel. */
async function rawApi(path) {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${state.token}` } });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body };
}

async function cognitoSignIn(email, password) {
  const res = await fetch(`https://cognito-idp.${state.config.region}.amazonaws.com/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth',
    },
    body: JSON.stringify({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: state.config.clientId,
      AuthParameters: { USERNAME: email, PASSWORD: password },
    }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.AuthenticationResult) {
    throw new Error(body.message || 'Sign-in failed');
  }
  return body.AuthenticationResult.IdToken;
}

function tokenExpiry(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload.exp * 1000;
  } catch { return 0; }
}

function saveToken(token) {
  state.token = token;
  try { sessionStorage.setItem('token', token); } catch { /* private mode: keep in memory */ }
}

function loadToken() {
  try {
    const t = sessionStorage.getItem('token');
    if (t && tokenExpiry(t) > Date.now() + 60_000) return t;
  } catch { /* ignore */ }
  return null;
}

function signOut(message) {
  stopPolling();
  state.token = null;
  state.me = null;
  try { sessionStorage.removeItem('token'); } catch { /* ignore */ }
  renderLogin(message);
}

// ---------------------------------------------------------------- sign-in view

function renderLogin(message) {
  const error = h('p', { class: 'error', role: 'alert' }, message || '');
  const email = h('input', { type: 'email', name: 'email', autocomplete: 'username', required: true });
  const password = h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true });
  const submit = h('button', { class: 'btn primary', type: 'submit' }, 'Sign in');

  const form = h('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      error.textContent = '';
      try {
        saveToken(await cognitoSignIn(email.value.trim(), password.value));
        await start();
      } catch (err) {
        error.textContent = err.message === 'Incorrect username or password.' ? err.message : `Sign-in failed: ${err.message}`;
        submit.disabled = false;
      }
    },
  },
  h('label', {}, 'Email', email),
  h('label', {}, 'Password', password),
  submit,
  error);

  const accounts = h('div', { class: 'accounts' },
    h('div', { class: 'small muted' }, 'Demo accounts (the password is in the message you were sent):'),
    h('ul', {}, DEMO_ACCOUNTS.map((a) => h('li', {},
      h('span', {}, a.label),
      h('button', { class: 'btn link', type: 'button', onclick: () => { email.value = a.email; password.focus(); } }, a.email)))));

  show(h('section', { class: 'panel login' },
    h('h1', {}, 'Unified Inbox'),
    h('p', { class: 'muted' }, 'Slack, SMS and in-app messages in one inbox, for two tenants that can’t see each other.'),
    form,
    accounts));
  email.focus();
}

// ---------------------------------------------------------------- signed-in shell

const TABS = [
  ['inbox', 'Inbox'],
  ['people', 'People'],
  ['search', 'Search'],
  ['audit', 'Audit log'],
  ['isolation', 'Isolation test'],
];

function renderShell() {
  const me = state.me;
  const header = h('header', { class: 'top' },
    h('h1', {}, 'Unified Inbox'),
    h('div', { class: 'who' },
      h('span', {}, me.display_name || me.username),
      h('span', { class: 'badge' }, `tenant: ${me.tenant_id}`),
      h('span', { class: `badge ${me.role === 'admin' ? 'ok' : ''}` }, me.role),
      h('button', { class: 'btn', onclick: () => signOut() }, 'Sign out')));

  const tabs = isPlatformAdmin() ? TABS.concat([['platform', 'Platform stats']]) : TABS;
  const nav = h('nav', { class: 'tabs', role: 'tablist' },
    tabs.map(([id, label]) => h('button', {
      role: 'tab',
      'aria-selected': state.tab === id ? 'true' : 'false',
      onclick: () => { state.tab = id; renderShell(); },
    }, label)));

  const body = h('div', { id: 'view' });
  show(header, nav, body,
    h('footer', { class: 'foot' }, 'Rust on AWS Lambda · DynamoDB · Cognito. Every request here is written to the audit log.'));

  stopPolling();
  ({ inbox: viewInbox, people: viewPeople, search: viewSearch, audit: viewAudit, isolation: viewIsolation, platform: viewPlatform })[state.tab](body);
}

function viewError(err) {
  const status = err instanceof ApiError ? ` (HTTP ${err.status})` : '';
  return h('div', { class: 'panel notice' }, h('p', { class: 'error' }, `Something went wrong${status}. Try again.`));
}

// ---------------------------------------------------------------- inbox

function senderName(m) {
  const s = m.sender || {};
  if (s.kind === 'user') {
    if (state.me && s.user_id === state.me.user_id) return 'You';
    return state.names.get(s.user_id) || 'Unknown user';
  }
  return s.display_name || s.address || 'External';
}

function messageNode(m, isNew) {
  const mine = m.sender && m.sender.kind === 'user' && state.me && m.sender.user_id === state.me.user_id;
  return h('div', { class: `msg${mine ? ' mine' : ''}${isNew ? ' new' : ''}`, 'data-id': m.message_id },
    h('div', { class: 'meta' },
      h('strong', {}, senderName(m)),
      channelBadge(m.channel),
      h('time', { datetime: m.sent_at }, time(m.sent_at))),
    h('div', { class: 'body' }, m.body_text));
}

async function viewInbox(root) {
  root.replaceChildren(h('p', { class: 'muted' }, 'Loading conversations…'));
  try {
    state.conversations = (await api('/conversations')).items;
  } catch (err) { root.replaceChildren(viewError(err)); return; }

  if (!state.conversations.length) {
    root.replaceChildren(h('div', { class: 'panel notice' }, 'You’re not in any conversations.'));
    return;
  }
  if (!state.conversations.some((c) => c.conversation_id === state.current)) {
    state.current = state.conversations[0].conversation_id;
  }

  const list = h('div', { class: 'panel convs', role: 'list' },
    state.conversations.map((c) => h('button', {
      role: 'listitem',
      'aria-current': c.conversation_id === state.current ? 'true' : 'false',
      onclick: () => { state.current = c.conversation_id; viewInbox(root); },
    },
    h('div', { class: 'name' }, c.name),
    h('div', { class: 'small muted when' }, c.last_message_at ? `Last message ${time(c.last_message_at)}` : 'No messages'))));

  const thread = h('section', { class: 'panel thread' });
  root.replaceChildren(h('div', { class: 'inbox' }, list, thread));
  await openConversation(thread);
}

async function openConversation(thread) {
  const conv = state.conversations.find((c) => c.conversation_id === state.current);
  const messages = h('div', { class: 'messages' }, h('p', { class: 'muted' }, 'Loading…'));
  const older = h('button', { class: 'btn link', onclick: () => loadOlder(messages, older) }, 'Load older');
  const count = h('div', { class: 'count' }, `0 / ${MAX_CHARS}`);
  const input = h('textarea', {
    rows: 2,
    maxlength: MAX_CHARS,
    placeholder: `Message ${conv.name}`,
    'aria-label': 'Message',
    oninput: () => { count.textContent = `${input.value.length} / ${MAX_CHARS}`; },
    onkeydown: (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } },
  });
  const send = h('button', { class: 'btn primary', type: 'submit' }, 'Send');
  const form = h('form', {
    class: 'composer',
    onsubmit: async (e) => {
      e.preventDefault();
      const text = input.value.trim();
      if (!text) return;
      send.disabled = true;
      try {
        const msg = await api(`/conversations/${encodeURIComponent(state.current)}/messages`, {
          method: 'POST',
          body: JSON.stringify({ text }),
        });
        input.value = '';
        count.textContent = `0 / ${MAX_CHARS}`;
        addMessages(messages, [msg]);
      } catch (err) {
        count.textContent = err instanceof ApiError && err.status === 400 ? 'Message must be 1–1000 characters.' : 'Couldn’t send. Try again.';
      } finally {
        send.disabled = false;
        input.focus();
      }
    },
  }, input, send, count);

  thread.replaceChildren(
    h('div', { class: 'thread-head' },
      h('strong', {}, conv.name),
      h('span', { class: 'small muted' }, 'New messages appear automatically')),
    messages,
    form);

  state.messages = [];
  try {
    const page = await api(`/conversations/${encodeURIComponent(state.current)}/messages?limit=20`);
    state.messages = page.items.slice().reverse();
    state.olderCursor = page.next_cursor;
    messages.replaceChildren(...state.messages.map((m) => messageNode(m, false)));
    if (state.olderCursor) messages.prepend(older);
    messages.scrollTop = messages.scrollHeight;
  } catch (err) {
    messages.replaceChildren(viewError(err));
    return;
  }
  startPolling(messages);
}

async function loadOlder(messages, button) {
  button.disabled = true;
  try {
    const page = await api(`/conversations/${encodeURIComponent(state.current)}/messages?limit=20&cursor=${encodeURIComponent(state.olderCursor)}`);
    const olderMsgs = page.items.slice().reverse();
    state.messages = olderMsgs.concat(state.messages);
    state.olderCursor = page.next_cursor;
    const firstBefore = messages.querySelector('.msg');
    olderMsgs.forEach((m) => messages.insertBefore(messageNode(m, false), firstBefore));
    if (!state.olderCursor) button.remove();
  } finally {
    button.disabled = false;
  }
}

function addMessages(container, incoming) {
  const known = new Set(state.messages.map((m) => m.message_id));
  const fresh = incoming.filter((m) => !known.has(m.message_id));
  if (!fresh.length) return;
  const atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 60;
  fresh.sort((a, b) => (a.message_id < b.message_id ? -1 : 1));
  state.messages.push(...fresh);
  fresh.forEach((m) => container.append(messageNode(m, true)));
  if (atBottom) container.scrollTop = container.scrollHeight;
}

function startPolling(container) {
  stopPolling();
  const conv = state.current;
  state.poll = setInterval(async () => {
    if (document.hidden || state.tab !== 'inbox' || state.current !== conv) return;
    try {
      const page = await api(`/conversations/${encodeURIComponent(conv)}/messages?limit=10`);
      addMessages(container, page.items);
    } catch { /* transient; next tick retries */ }
  }, POLL_MS);
}

function stopPolling() {
  if (state.poll) clearInterval(state.poll);
  state.poll = null;
}

// ---------------------------------------------------------------- people

async function viewPeople(root) {
  root.replaceChildren(h('p', { class: 'muted' }, 'Loading…'));
  try {
    const { items } = await api('/people');
    root.replaceChildren(
      h('p', { class: 'muted small' }, 'People you share conversations with, and how many. A two-hop query: your conversations, then their members.'),
      h('div', { class: 'panel list' },
        items.length
          ? items.map((p) => h('div', { class: 'row' },
            h('div', {}, h('div', {}, p.display_name || 'Unknown'), h('div', { class: 'small muted' }, p.email || '')),
            h('span', { class: 'badge' }, `${p.shared} shared`)))
          : h('div', { class: 'row muted' }, 'Nobody yet.')));
  } catch (err) { root.replaceChildren(viewError(err)); }
}

// ---------------------------------------------------------------- search

function highlight(text, query) {
  const out = [];
  const lower = text.toLowerCase();
  const q = query.toLowerCase();
  let i = 0;
  for (let at = lower.indexOf(q); q && at !== -1; at = lower.indexOf(q, i)) {
    out.push(text.slice(i, at), h('mark', {}, text.slice(at, at + q.length)));
    i = at + q.length;
  }
  out.push(text.slice(i));
  return out;
}

function viewSearch(root) {
  const input = h('input', { type: 'search', placeholder: 'Search your conversations (try “outage”)', 'aria-label': 'Search' });
  const results = h('div', {});
  const names = new Map(state.conversations.map((c) => [c.conversation_id, c.name]));
  const form = h('form', {
    class: 'toolbar',
    onsubmit: async (e) => {
      e.preventDefault();
      const q = input.value.trim();
      if (q.length < 2) { results.replaceChildren(h('p', { class: 'muted' }, 'Type at least 2 characters.')); return; }
      results.replaceChildren(h('p', { class: 'muted' }, 'Searching…'));
      try {
        const { items } = await api(`/search?q=${encodeURIComponent(q)}`);
        results.replaceChildren(
          h('p', { class: 'muted small' }, `${items.length} result${items.length === 1 ? '' : 's'}, only from conversations you’re in.`),
          h('div', { class: 'panel list' },
            items.length
              ? items.map((m) => h('div', { class: 'row' },
                h('div', {},
                  h('div', { class: 'small muted' }, names.get(m.conversation_id) || m.conversation_id, ' · ', time(m.sent_at)),
                  h('div', {}, highlight(m.body_text, q))),
                channelBadge(m.channel)))
              : h('div', { class: 'row muted' }, 'No matches.')));
      } catch (err) { results.replaceChildren(viewError(err)); }
    },
  }, input, h('button', { class: 'btn primary', type: 'submit' }, 'Search'));
  root.replaceChildren(form, results);
  input.focus();
}

// ---------------------------------------------------------------- audit

function viewAudit(root) {
  const today = new Date().toISOString().slice(0, 10);
  const date = h('input', { type: 'date', value: today, max: today, 'aria-label': 'Day' });
  const out = h('div', {});
  const load = async () => {
    out.replaceChildren(h('p', { class: 'muted' }, 'Loading…'));
    try {
      const { items } = await api(`/audit?limit=100&date=${encodeURIComponent(date.value)}`);
      out.replaceChildren(
        h('p', { class: 'muted small' }, `${items.length} most recent records for ${state.me.tenant_id} (UTC day ${date.value}). The app can only append to this log; the tamper-proof copy belongs in an Object Lock archive.`),
        h('div', { class: 'panel table-wrap' },
          h('table', {},
            h('thead', {}, h('tr', {}, ['Time', 'Actor', 'Action', 'Outcome', 'Reason', 'Resource', 'Record hash'].map((t) => h('th', {}, t)))),
            h('tbody', {}, items.map((r) => h('tr', {},
              h('td', {}, time(r.ts)),
              h('td', {}, (r.actor && (r.actor.username || r.actor.type)) || ''),
              h('td', { class: 'mono' }, r.action),
              h('td', {}, outcomeBadge(r.outcome)),
              h('td', { class: 'small' }, r.reason || ''),
              h('td', { class: 'small' }, r.resource ? `${r.resource.type} ${r.resource.id}` : ''),
              h('td', { class: 'hash small' }, (r.record_hash || '').slice(7, 19))))))));
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        out.replaceChildren(h('div', { class: 'panel notice' },
          h('h2', {}, 'Admins only'),
          h('p', {}, 'Only tenant admins can read the audit log. The API answered 403, and this attempt was itself written to the audit log.'),
          h('p', { class: 'muted small' }, 'Sign in as an admin (alice or dave) to see it.')));
      } else {
        out.replaceChildren(viewError(err));
      }
    }
  };
  date.addEventListener('change', load);
  root.replaceChildren(h('div', { class: 'toolbar' }, date, h('button', { class: 'btn', onclick: load }, 'Refresh')), out);
  load();
}

// ---------------------------------------------------------------- isolation test

function viewIsolation(root) {
  const tenant = state.me.tenant_id;
  const other = OTHER_TENANT[tenant] || 'globex';
  const foreignConv = FOREIGN_CONVERSATION[tenant] || 'c_ward';

  const card = (title, text, buttonLabel, path, judge) => {
    const result = h('div', {});
    const button = h('button', {
      class: 'btn primary',
      onclick: async () => {
        button.disabled = true;
        result.replaceChildren(h('p', { class: 'muted' }, 'Calling…'));
        const res = await rawApi(path);
        const [ok, verdict] = judge(res);
        result.replaceChildren(
          h('p', { class: `verdict ${ok ? 'ok' : 'bad'}` }, verdict),
          h('div', { class: 'small muted' }, `GET ${path} → HTTP ${res.status}`),
          h('pre', { class: 'response' }, JSON.stringify(res.body, null, 2)));
        button.disabled = false;
      },
    }, buttonLabel);
    return h('section', { class: 'panel card' }, h('h2', {}, title), h('p', {}, text), h('div', {}, button), result);
  };

  root.replaceChildren(
    h('p', { class: 'muted' }, `You’re signed in to ${tenant}. These try to read ${other}’s data, and both attempts go into ${tenant}’s audit log.`),
    h('div', { class: 'cards' },
      card(
        `Ask for a ${other} conversation`,
        `Requests ${other}’s conversation “${foreignConv}” through the normal API. The app checks membership in your tenant and answers exactly as it would for a conversation that doesn’t exist.`,
        'Try it',
        `/conversations/${foreignConv}/messages`,
        (r) => (r.status === 404 ? [true, 'Blocked: 404, indistinguishable from “doesn’t exist”.'] : [false, 'Unexpected response.'])),
      card(
        'Bypass the app: the IAM probe',
        `Skips every check in the code and reads ${other}’s data directly from DynamoDB, using the credentials your request runs with. Those credentials are tagged with your tenant, and IAM only allows keys that start with T#${tenant}#.`,
        'Run the probe',
        `/debug/probe?tenant=${other}`,
        (r) => (r.body && r.body.blocked_by === 'iam'
          ? [true, 'Blocked by IAM: DynamoDB itself refused (AccessDeniedException).']
          : [false, 'Not blocked by IAM. That would be an isolation failure.']))));
}

// ---------------------------------------------------------------- platform stats

function isPlatformAdmin() {
  return Boolean(state.me && (state.me.groups || []).includes('platform-admin'));
}

async function viewPlatform(root) {
  root.replaceChildren(h('p', { class: 'muted' }, 'Loading…'));
  try {
    const { days } = await api('/platform/stats?days=7');
    const channels = ['slack', 'sms', 'native'];
    const rows = days.flatMap((d) => d.tenants.map((t) => h('tr', {},
      h('td', {}, d.date),
      h('td', {}, t.tenant_id),
      channels.map((c) => h('td', {}, String(t.messages[c] || 0))),
      h('td', {}, h('strong', {}, String(t.total))))));
    root.replaceChildren(
      h('p', { class: 'muted small' },
        'Message counts per tenant for the last 7 days (UTC). This is the one cross-tenant view, and it is content-free: '
        + 'it runs under a separate role that can only read PLATFORM# counter items, so it could not read a message even if the code asked. '
        + 'Only the platform-admin group can open it, and every view is audited.'),
      h('div', { class: 'panel table-wrap' },
        h('table', {},
          h('thead', {}, h('tr', {}, ['Day', 'Tenant', 'Slack', 'SMS', 'App', 'Total'].map((t) => h('th', {}, t)))),
          h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'No messages yet.'))))));
  } catch (err) {
    root.replaceChildren(err instanceof ApiError && err.status === 403
      ? h('div', { class: 'panel notice' }, h('h2', {}, 'Platform admins only'), h('p', {}, 'The attempt was audited.'))
      : viewError(err));
  }
}

// ---------------------------------------------------------------- start

async function start() {
  state.me = await api('/me');
  state.names = new Map([[state.me.user_id, state.me.display_name || state.me.username]]);
  try {
    const { items } = await api('/people');
    items.forEach((p) => state.names.set(p.user_id, p.display_name || p.email));
  } catch { /* names are cosmetic */ }
  state.tab = 'inbox';
  renderShell();
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch('/config.json');
    state.config = await res.json();
  } catch {
    show(h('p', { class: 'error center' }, 'Couldn’t load configuration.'));
    return;
  }
  const token = loadToken();
  if (!token) { renderLogin(); return; }
  state.token = token;
  try { await start(); } catch { signOut(); }
});

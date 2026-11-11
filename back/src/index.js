import { Hono } from 'hono';
import { createYoga, createSchema } from 'graphql-yoga';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { GraphQLJSON } from 'graphql-type-json';
import { DateTimeResolver } from 'graphql-scalars';
import { Bot, webhookCallback } from 'grammy';
import { GraphQLScalarType, Kind, GraphQLError } from 'graphql';

// ----------------------------------------------------
// BigInt Custom Resolver
// ----------------------------------------------------
const BigIntResolver = {
  BigInt: new GraphQLScalarType({
    name: 'BigInt',
    description: 'BigInt custom scalar type',
    serialize(value) {
      if (value === null || value === undefined) return null;
      return value.toString();
    },
    parseValue(value) {
      if (value === null || value === undefined) return null;
      return value.toString();
    },
    parseLiteral(ast) {
      if (ast.kind === Kind.STRING || ast.kind === Kind.INT) {
        return ast.value;
      }
      return null;
    },
  }),
};

// ----------------------------------------------------
// GraphQL Schema Definitions
// ----------------------------------------------------
const typeDefs = `
  scalar JSON
  scalar Date
  scalar DateTime
  scalar BigInt

  type User {
    id: ID!
    username: String!
    number_id: BigInt
    first_name: String
    last_name: String
    created_at: DateTime!
    updated_at: DateTime!
  }

  type Company {
    id: ID!
    owner_user_id: ID
    name: String!
    slug: String
    description: String
    data: JSON!
    created_at: DateTime!
    updated_at: DateTime!
    domains: [Domain!]!
    people: [People!]!
  }

  type Domain {
    id: ID!
    company_id: ID!
    host: String!
    canonical_url: String
    data: JSON!
    created_at: DateTime!
    updated_at: DateTime!
    company: Company!
  }

  type People {
    id: ID!
    company_id: ID
    created_by: ID
    given_name: String
    family_name: String
    emails: [String!]!
    phones: [String!]!
    notes: String
    data: JSON!
    created_at: DateTime!
    company: Company
    creator: User
  }

  input PeopleInput {
    company_id: ID!
    given_name: String
    family_name: String
    emails: [String!]
    phones: [String!]
    notes: String
    data: JSON
  }

  input CompanyInput {
    name: String!
    slug: String
    description: String
    owner_user_id: ID
    data: JSON
  }

  input DomainInput {
    company_id: ID!
    host: String!
    canonical_url: String
    data: JSON
  }

  type CompanyMap {
    id: ID!
    domain: String!
    ips: JSON
    ports: JSON
    services: JSON
    domains: [DomainMap]
  }

  type DomainMap {
    url: String
    host: String
    status_code: Int
  }

  type OngoingRecon {
    domain: String!
    status: String!
  }

  type Finding {
    id: ID!
    domain_id: ID
    company_id: ID
    tool: String!
    severity: String!
    vuln_type: String!
    title: String!
    url: String
    description: String
    evidence: String
    poc: String
    cve: String
    status: String!
    created_at: DateTime!
    updated_at: DateTime!
  }

  type Endpoint {
    id: ID!
    domain_id: ID
    url: String!
    method: String
    params: JSON
    status_code: Int
    content_type: String
    source: String
    created_at: DateTime!
  }

  type Secret {
    id: ID!
    domain_id: ID
    rule_name: String!
    secret_type: String!
    match_snippet: String!
    file_url: String
    severity: String!
    status: String!
    created_at: DateTime!
  }

  type NetworkService {
    id: ID!
    domain_id: ID
    ip: String!
    port: Int!
    protocol: String
    service: String
    product: String
    version: String
    banner: String
    created_at: DateTime!
  }

  input FindingInput {
    id: ID
    tool: String!
    severity: String!
    vuln_type: String!
    title: String!
    url: String
    description: String
    evidence: String
    poc: String
    cve: String
    status: String
  }

  input EndpointInput {
    id: ID
    url: String!
    method: String
    params: JSON
    status_code: Int
    content_type: String
    source: String
  }

  input SecretInput {
    id: ID
    rule_name: String!
    secret_type: String!
    match_snippet: String!
    file_url: String
    severity: String
    status: String
  }

  input NetworkServiceInput {
    id: ID
    ip: String!
    port: Int!
    protocol: String
    service: String
    product: String
    version: String
    banner: String
  }

  # ---- Team workflows ----
  type ApiToken {
    id: ID!
    user_id: ID
    name: String!
    role: String!
    revoked: Boolean!
    last_used_at: DateTime
    created_at: DateTime!
    token: String   # plaintext, returned only once at creation
    user: User
  }

  type Campaign {
    id: ID!
    name: String!
    slug: String
    owner_user_id: ID
    company_id: ID
    kind: String!
    status: String!
    authorized: Boolean!
    scope: JSON!
    description: String
    data: JSON!
    created_at: DateTime!
    updated_at: DateTime!
    owner: User
    company: Company
    members: [CampaignMember!]!
    targetGroups: [TargetGroup!]!
    playbooks: [Playbook!]!
  }

  type CampaignMember {
    campaign_id: ID!
    user_id: ID!
    role: String!
    created_at: DateTime!
    user: User
  }

  type TargetGroup {
    id: ID!
    campaign_id: ID
    name: String!
    owner_user_id: ID
    visibility: String!
    description: String
    data: JSON!
    created_at: DateTime!
    updated_at: DateTime!
    domains: [Domain!]!
    campaign: Campaign
  }

  type JobTemplate {
    id: ID!
    name: String!
    slug: String
    owner_user_id: ID
    visibility: String!
    command_template: String!
    phases: JSON!
    default_flags: JSON!
    runner: String
    description: String
    data: JSON!
    created_at: DateTime!
    updated_at: DateTime!
  }

  type Playbook {
    id: ID!
    name: String!
    slug: String
    campaign_id: ID
    owner_user_id: ID
    visibility: String!
    description: String
    data: JSON!
    created_at: DateTime!
    updated_at: DateTime!
    steps: [PlaybookStep!]!
    campaign: Campaign
  }

  type PlaybookStep {
    id: ID!
    playbook_id: ID!
    step_order: Int!
    template_id: ID
    phase: String
    params: JSON!
    created_at: DateTime!
    template: JobTemplate
  }

  type RunResult {
    jobIds: [ID!]!
    count: Int!
  }

  input CampaignInput {
    name: String!
    slug: String
    owner_user_id: ID
    company_id: ID
    kind: String
    status: String
    authorized: Boolean
    scope: JSON
    description: String
    data: JSON
  }

  input TargetGroupInput {
    name: String!
    campaign_id: ID
    owner_user_id: ID
    visibility: String
    description: String
    data: JSON
  }

  input JobTemplateInput {
    name: String!
    slug: String
    command_template: String!
    phases: JSON
    default_flags: JSON
    runner: String
    visibility: String
    description: String
    data: JSON
  }

  input PlaybookInput {
    name: String!
    slug: String
    campaign_id: ID
    visibility: String
    description: String
    data: JSON
  }

  input PlaybookStepInput {
    step_order: Int!
    template_id: ID
    phase: String
    params: JSON
  }

  type Query {
    me: User
    user(id: ID, username: String, number_id: BigInt): User
    users: [User!]!

    companies: [Company!]!
    company(id: ID!): Company
    companyBySlug(slug: String!): Company
    companyByName(name: String!): Company
    companiesByOwner(ownerUserId: ID!): [Company!]!

    domains: [Domain!]!
    domain(id: ID!): Domain
    domainsByCompany(companyId: ID!): [Domain!]!
    domainByHost(host: String!): Domain
    domainsByStatusCode(statusCode: Int!): [Domain!]!

    people: [People!]!
    person(id: ID!): People
    peopleByCompany(companyId: ID!): [People!]!
    peopleByName(givenName: String, familyName: String): [People!]!
    peopleByPhone(phone: String!): [People!]!

    map: [CompanyMap]
    personByEmail(email: String!): People
    
    # Scanner queries
    domainsToScan: [Company!]!
    ongoingJobs: [ScanJob!]!
    findings(domain: String, severity: String): [Finding!]!
    secrets(domain: String): [Secret!]!
    endpoints(domain: String, limit: Int): [Endpoint!]!
    networkServices(domain: String): [NetworkService!]!
    domainReport(domain: String!): JSON!

    # Team workflows
    campaigns(status: String, kind: String): [Campaign!]!
    campaign(id: ID!): Campaign
    campaignBySlug(slug: String!): Campaign
    targetGroups(campaignId: ID): [TargetGroup!]!
    targetGroup(id: ID!): TargetGroup
    jobTemplates: [JobTemplate!]!
    jobTemplate(id: ID!): JobTemplate
    playbooks(campaignId: ID): [Playbook!]!
    playbook(id: ID!): Playbook
    apiTokens: [ApiToken!]!
  }

  type Mutation {
    createUser(username: String!, number_id: BigInt, first_name: String, last_name: String): User!
    updateUser(id: ID!, username: String, number_id: BigInt, first_name: String, last_name: String): User!
    deleteUser(id: ID!): Boolean!

    createCompany(input: CompanyInput!): Company!
    updateCompany(id: ID!, input: CompanyInput!): Company!
    deleteCompany(id: ID!): Boolean!

    createDomain(input: DomainInput!): Domain!
    updateDomain(id: ID!, input: DomainInput!): Domain!
    deleteDomain(id: ID!): Boolean!

    createPeople(input: PeopleInput!): People!
    updatePeople(id: ID!, input: PeopleInput!): People!
    deletePeople(id: ID!): Boolean!

    # Scanner mutations
    updateHttpxResults(domain: String!, results: [JSON!]!): Boolean!
    updatePortScanResults(domain: String!, ports: JSON!, ips: JSON!): Boolean!
    updateKatanaResults(domain: String!, results: [JSON!]!): Boolean!
    updateNucleiResults(domain: String!, results: JSON!): Boolean!
    updateJsResults(domain: String!, results: [JSON!]!): Boolean!
    updateExposureResults(domain: String!, results: [JSON!]!): Boolean!
    updateTakeoverResults(domain: String!, results: [JSON!]!): Boolean!
    createFindingsBatch(domain: String!, findings: [FindingInput!]!): Boolean!
    createEndpointsBatch(domain: String!, endpoints: [EndpointInput!]!): Boolean!
    createSecretsBatch(domain: String!, secrets: [SecretInput!]!): Boolean!
    createNetworkServicesBatch(domain: String!, services: [NetworkServiceInput!]!): Boolean!

    # ---- Team workflows ----
    createApiToken(userId: ID, name: String!, role: String): ApiToken!
    revokeApiToken(id: ID!): Boolean!

    createCampaign(input: CampaignInput!): Campaign!
    updateCampaign(id: ID!, input: CampaignInput!): Campaign!
    deleteCampaign(id: ID!): Boolean!
    setCampaignStatus(id: ID!, status: String!): Campaign!
    addCampaignMember(campaignId: ID!, userId: ID!, role: String): CampaignMember!
    removeCampaignMember(campaignId: ID!, userId: ID!): Boolean!

    createTargetGroup(input: TargetGroupInput!): TargetGroup!
    updateTargetGroup(id: ID!, input: TargetGroupInput!): TargetGroup!
    deleteTargetGroup(id: ID!): Boolean!
    addDomainToGroup(groupId: ID!, domainId: ID!): Boolean!
    removeDomainFromGroup(groupId: ID!, domainId: ID!): Boolean!

    createJobTemplate(input: JobTemplateInput!): JobTemplate!
    updateJobTemplate(id: ID!, input: JobTemplateInput!): JobTemplate!
    deleteJobTemplate(id: ID!): Boolean!

    createPlaybook(input: PlaybookInput!): Playbook!
    updatePlaybook(id: ID!, input: PlaybookInput!): Playbook!
    deletePlaybook(id: ID!): Boolean!
    setPlaybookSteps(playbookId: ID!, steps: [PlaybookStepInput!]!): Playbook!
    bindPlaybookToTarget(playbookId: ID!, domainId: ID, groupId: ID): Boolean!

    runTemplate(templateId: ID!, target: String!, runner: String, senderId: BigInt): RunResult!
    runPlaybook(playbookId: ID!, target: String, groupId: ID, runner: String, senderId: BigInt): RunResult!
  }

  type Subscription {
    companyUpdated: Company
    domainUpdated: Domain
    peopleUpdated: People
    
    map: [CompanyMap]
    scriptOutput(jobId: ID!): String
    ongoingRecons: [OngoingRecon]
  }

  type ScanJob {
    id: ID!
    command: String!
    domain: String!
    runner: String
    status: String!
    stdout: String
    phase: String
    created_at: String
    updated_at: String
  }
`;

// Helper to safely parse JSON strings
const parseJson = (val) => {
  if (val === null || val === undefined) return {};
  if (typeof val === 'object') return val;
  try {
    return JSON.parse(val || '{}');
  } catch (e) {
    return {};
  }
};

// Helper to coerce a JSON-array column to an array (default [])
const parseJsonArray = (val) => {
  if (Array.isArray(val)) return val;
  if (val === null || val === undefined) return [];
  try {
    const p = JSON.parse(val || '[]');
    return Array.isArray(p) ? p : [];
  } catch (e) {
    return [];
  }
};

// ----------------------------------------------------
// Auth helpers: API-token (Bearer) auth + role enforcement
// ----------------------------------------------------
const sha256hex = async (str) => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
};

const extractToken = (request) => {
  if (!request || !request.headers) return null;
  const auth = request.headers.get('authorization');
  if (auth && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  const key = request.headers.get('x-api-key');
  return key ? key.trim() : null;
};

// Resolve the caller from an API token. Returns { userId, username, role, tokenId } or null.
const resolveAuth = async (env, request) => {
  const raw = extractToken(request);
  if (!raw) return null;
  try {
    const hash = await sha256hex(raw);
    const row = await env.DB.prepare(
      `SELECT t.id AS token_id, t.role AS token_role, t.revoked,
              u.id AS user_id, u.role AS user_role, u.username AS username
       FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
       WHERE t.token_hash = ?`
    ).bind(hash).first();
    if (!row || row.revoked) return null;
    // Best-effort last-used stamp; never block the request on it.
    env.DB.prepare("UPDATE api_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
      .bind(row.token_id).run().catch(() => {});
    // Token role scopes at or below the user's role; fall back to user role.
    return { userId: row.user_id, username: row.username, role: row.token_role || row.user_role || 'member', tokenId: row.token_id };
  } catch (e) {
    console.error('auth resolve error:', e.message);
    return null;
  }
};

// Auth is only enforced when AUTH_ENFORCED=true, so existing single-operator
// deployments keep working until they provision tokens and opt in.
const authEnforced = (env) => String(env?.AUTH_ENFORCED || '').toLowerCase() === 'true';

// Role ranking for API-token / GraphQL auth (distinct from the Telegram RBAC
// ROLE_RANK below, which uses the pending<viewer<operator<admin<superadmin model).
const TOKEN_ROLE_RANK = { viewer: 1, runner: 1, member: 2, admin: 3 };

// Throw unless the caller meets the minimum role (no-op in bootstrap mode).
const requireRole = (ctx, min) => {
  if (!authEnforced(ctx.env)) return;
  const role = ctx.auth?.role;
  if (!role) {
    throw new GraphQLError('Authentication required', { extensions: { code: 'UNAUTHENTICATED' } });
  }
  if ((TOKEN_ROLE_RANK[role] || 0) < (TOKEN_ROLE_RANK[min] || 99)) {
    throw new GraphQLError(`Insufficient role: '${min}' required`, { extensions: { code: 'FORBIDDEN' } });
  }
};

// Owner-or-admin check for mutating a specific row (no-op in bootstrap mode).
const requireOwnerOrAdmin = (ctx, ownerUserId) => {
  if (!authEnforced(ctx.env)) return;
  if (ctx.auth?.role === 'admin') return;
  if (ctx.auth?.userId && ownerUserId && ctx.auth.userId === ownerUserId) return;
  throw new GraphQLError('Only the owner or an admin may perform this action', { extensions: { code: 'FORBIDDEN' } });
};

const slugify = (s) => String(s || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);

// Reject targets that could break out of the runner's shell command.
const assertSafeTarget = (target) => {
  const t = String(target || '').trim();
  if (!t || /[;&|`$<>\n\r\\"'\s]/.test(t)) {
    throw new GraphQLError('Invalid target: empty or contains disallowed characters', { extensions: { code: 'BAD_USER_INPUT' } });
  }
  return t;
};

// Map a playbook phase identifier to the cHack.sh flag that runs it.
const PHASE_FLAGS = {
  recon: '-d', full: '-d', vulns: '-d',
  web: '--web', secrets: '--web',
  network: '--network', ports: '--network',
  infogather: '--info-gather', info: '--info-gather',
};
const commandForPhase = (phase, target, sender) => {
  const p = String(phase || 'recon').toLowerCase();
  const flag = PHASE_FLAGS[p] || `--${p}`;
  const s = (sender !== undefined && sender !== null && sender !== '') ? ` --sender-id ${sender}` : '';
  return `${flag} ${target}${s}`.trim();
};

// Expand a job-template command string, substituting {{target}} / {{sender}}.
const expandCommandTemplate = (tpl, target, sender) => {
  let out = String(tpl || '');
  out = out.replace(/\{\{\s*target\s*\}\}/gi, target != null ? String(target) : '');
  out = out.replace(/\{\{\s*sender(?:[-_]?id)?\s*\}\}/gi, (sender != null && sender !== '') ? String(sender) : '');
  return out.replace(/\s+/g, ' ').trim();
};

// Queue a single scan job and return its id.
const queueJob = async (env, command, domain, runner) => {
  const id = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO scan_jobs (id, command, domain, runner, status) VALUES (?, ?, ?, ?, 'pending')"
  ).bind(id, command, domain, runner || 'default').run();
  return id;
};

const resolvers = {
  ...BigIntResolver,
  JSON: GraphQLJSON,
  DateTime: DateTimeResolver,

  Query: {
    user: async (_, { id, username, number_id }, { env }) => {
      if (id) {
        return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
      }
      if (username) {
        return await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
      }
      if (number_id) {
        return await env.DB.prepare("SELECT * FROM users WHERE number_id = ?").bind(Number(number_id)).first();
      }
      return null;
    },
    users: async (_, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
      return results;
    },
    companies: async (_, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM companies ORDER BY created_at DESC").all();
      return results;
    },
    company: async (_, { id }, { env }) => {
      return await env.DB.prepare("SELECT * FROM companies WHERE id = ?").bind(id).first();
    },
    companyBySlug: async (_, { slug }, { env }) => {
      return await env.DB.prepare("SELECT * FROM companies WHERE slug = ?").bind(slug).first();
    },
    companyByName: async (_, { name }, { env }) => {
      return await env.DB.prepare("SELECT * FROM companies WHERE name = ?").bind(name).first();
    },
    companiesByOwner: async (_, { ownerUserId }, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM companies WHERE owner_user_id = ? ORDER BY created_at DESC").bind(ownerUserId).all();
      return results;
    },
    domains: async (_, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM domains ORDER BY created_at DESC").all();
      return results;
    },
    domain: async (_, { id }, { env }) => {
      return await env.DB.prepare("SELECT * FROM domains WHERE id = ?").bind(id).first();
    },
    domainsByCompany: async (_, { companyId }, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM domains WHERE company_id = ? ORDER BY created_at DESC").bind(companyId).all();
      return results;
    },
    domainByHost: async (_, { host }, { env }) => {
      return await env.DB.prepare("SELECT * FROM domains WHERE lower(host) = lower(?)").bind(host).first();
    },
    domainsByStatusCode: async (_, { statusCode }, { env }) => {
      // D1/SQLite doesn't support ->> operator easily, but it supports json_extract()
      const { results } = await env.DB.prepare(
        "SELECT * FROM domains WHERE CAST(json_extract(data, '$.status_code') AS INTEGER) = ? ORDER BY created_at DESC"
      ).bind(statusCode).all();
      return results;
    },
    people: async (_, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM people ORDER BY created_at DESC").all();
      return results;
    },
    person: async (_, { id }, { env }) => {
      return await env.DB.prepare("SELECT * FROM people WHERE id = ?").bind(id).first();
    },
    peopleByCompany: async (_, { companyId }, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM people WHERE company_id = ? ORDER BY created_at DESC").bind(companyId).all();
      return results;
    },
    peopleByName: async (_, { givenName, familyName }, { env }) => {
      let query = "SELECT * FROM people WHERE 1=1";
      const params = [];
      if (givenName) {
        params.push(givenName);
        query += ` AND given_name = ?`;
      }
      if (familyName) {
        params.push(familyName);
        query += ` AND family_name = ?`;
      }
      query += " ORDER BY created_at DESC";
      const { results } = await env.DB.prepare(query).bind(...params).all();
      return results;
    },
    peopleByPhone: async (_, { phone }, { env }) => {
      // In SQLite, we store phones as a JSON string like '["+123456"]'
      const { results } = await env.DB.prepare(
        "SELECT p.* FROM people p, json_each(p.phones) WHERE json_each.value = ? ORDER BY p.created_at DESC"
      ).bind(phone).all();
      return results;
    },
    map: async (_, __, { env }) => {
      const { results: companies } = await env.DB.prepare("SELECT * FROM companies").all();
      const result = [];
      for (const company of companies) {
        const { results: domains } = await env.DB.prepare(
          "SELECT host FROM domains WHERE company_id = ?"
        ).bind(company.id).all();
        result.push({
          id: company.id,
          domain: company.name,
          domains: domains.map(d => ({ host: d.host })),
        });
      }
      return result;
    },
    personByEmail: async (_, { email }, { env }) => {
      return await env.DB.prepare(
        "SELECT p.* FROM people p, json_each(p.emails) WHERE json_each.value = ? LIMIT 1"
      ).bind(email).first();
    },
    domainsToScan: async (_, __, { env }) => {
      const { results } = await env.DB.prepare(
        "SELECT * FROM companies WHERE created_at = updated_at ORDER BY slug"
      ).all();
      return results;
    },
    ongoingJobs: async (_, __, { env }) => {
      const { results: jobs } = await env.DB.prepare(
        "SELECT * FROM scan_jobs WHERE status IN ('pending', 'running') ORDER BY created_at DESC"
      ).all();
      
      const enrichedJobs = [];
      for (const job of jobs) {
        let phase = '1';
        if (job.status === 'pending') {
          phase = '1 (Pending)';
        } else {
          const stdout = job.stdout || '';
          if (stdout.includes('Phase 5') || stdout.includes('Vulnerability Scan') || stdout.includes('Finalizing Scan')) {
            phase = '5';
          } else if (stdout.includes('Phase 4') || stdout.includes('URL Discovery') || stdout.includes('Crawler findings') || stdout.includes('Katana')) {
            phase = '4';
          } else if (stdout.includes('Phase 3') || stdout.includes('Port Scan') || stdout.includes('Port Scan findings')) {
            phase = '3';
          } else if (stdout.includes('Phase 2') || stdout.includes('HTTPX Scan') || stdout.includes('HTTPX findings')) {
            phase = '2';
          } else {
            try {
              let company = null;
              const domRow = await env.DB.prepare(
                "SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1"
              ).bind(job.domain).first();
              
              if (domRow) {
                company = await env.DB.prepare(
                  "SELECT data FROM companies WHERE id = ?"
                ).bind(domRow.company_id).first();
              } else {
                company = await env.DB.prepare(
                  "SELECT data FROM companies WHERE lower(name) = lower(?) OR lower(slug) = lower(?) LIMIT 1"
                ).bind(job.domain, job.domain).first();
              }
              
              if (company && company.data) {
                const compData = typeof company.data === 'string' ? JSON.parse(company.data) : company.data;
                if (compData && compData.phase) {
                  phase = compData.phase;
                }
              }
            } catch (e) {
              console.error("Error fetching phase:", e.message);
            }
          }
        }
        
        enrichedJobs.push({
          id: job.id,
          command: job.command,
          domain: job.domain,
          runner: job.runner || 'default',
          status: job.status,
          stdout: job.stdout || '',
          phase: String(phase),
          created_at: job.created_at,
          updated_at: job.updated_at
        });
      }
      return enrichedJobs;
    },
    findings: async (_, { domain, severity }, { env }) => {
      let query = `
        SELECT f.* FROM findings f
        JOIN domains d ON f.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE 1=1
      `;
      const binds = [];
      if (domain) {
        query += " AND (lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?))";
        binds.push(domain, domain, domain);
      }
      if (severity) {
        query += " AND lower(f.severity) = lower(?)";
        binds.push(severity);
      }
      query += " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.created_at DESC";
      const { results } = await env.DB.prepare(query).bind(...binds).all();
      return results;
    },
    secrets: async (_, { domain }, { env }) => {
      let query = `
        SELECT s.* FROM secrets s
        JOIN domains d ON s.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE 1=1
      `;
      const binds = [];
      if (domain) {
        query += " AND (lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?))";
        binds.push(domain, domain, domain);
      }
      query += " ORDER BY s.created_at DESC";
      const { results } = await env.DB.prepare(query).bind(...binds).all();
      return results;
    },
    endpoints: async (_, { domain, limit = 200 }, { env }) => {
      let query = `
        SELECT e.* FROM endpoints e
        JOIN domains d ON e.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE 1=1
      `;
      const binds = [];
      if (domain) {
        query += " AND (lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?))";
        binds.push(domain, domain, domain);
      }
      query += " ORDER BY e.created_at DESC LIMIT ?";
      binds.push(limit);
      const { results } = await env.DB.prepare(query).bind(...binds).all();
      return results;
    },
    networkServices: async (_, { domain }, { env }) => {
      let query = `
        SELECT ns.* FROM network_services ns
        JOIN domains d ON ns.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE 1=1
      `;
      const binds = [];
      if (domain) {
        query += " AND (lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?))";
        binds.push(domain, domain, domain);
      }
      query += " ORDER BY ns.port ASC";
      const { results } = await env.DB.prepare(query).bind(...binds).all();
      return results;
    },
    domainReport: async (_, { domain }, { env }) => {
      const dom = await env.DB.prepare("SELECT * FROM domains WHERE lower(host) = lower(?)").bind(domain).first();
      const comp = await env.DB.prepare("SELECT * FROM companies WHERE lower(name) = lower(?) OR lower(slug) = lower(?)").bind(domain, domain).first();
      const companyId = dom ? dom.company_id : (comp ? comp.id : null);
      
      const { results: findings } = await env.DB.prepare(`
        SELECT f.* FROM findings f
        JOIN domains d ON f.domain_id = d.id
        WHERE lower(d.host) = lower(?) OR d.company_id = ?
      `).bind(domain, companyId).all();

      const { results: secrets } = await env.DB.prepare(`
        SELECT s.* FROM secrets s
        JOIN domains d ON s.domain_id = d.id
        WHERE lower(d.host) = lower(?) OR d.company_id = ?
      `).bind(domain, companyId).all();

      const { results: services } = await env.DB.prepare(`
        SELECT ns.* FROM network_services ns
        JOIN domains d ON ns.domain_id = d.id
        WHERE lower(d.host) = lower(?) OR d.company_id = ?
      `).bind(domain, companyId).all();

      const stats = {
        critical: findings.filter(f => f.severity.toLowerCase() === 'critical').length,
        high: findings.filter(f => f.severity.toLowerCase() === 'high').length,
        medium: findings.filter(f => f.severity.toLowerCase() === 'medium').length,
        low: findings.filter(f => f.severity.toLowerCase() === 'low').length,
        info: findings.filter(f => f.severity.toLowerCase() === 'info').length,
        secrets: secrets.length,
        services: services.length,
      };

      return {
        domain,
        stats,
        findings,
        secrets,
        services
      };
    },

    // ---- Team workflows ----
    me: async (_, __, { env, auth }) => {
      if (!auth?.userId) return null;
      return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(auth.userId).first();
    },
    campaigns: async (_, { status, kind }, { env }) => {
      let q = "SELECT * FROM campaigns WHERE 1=1";
      const binds = [];
      if (status) { q += " AND status = ?"; binds.push(status); }
      if (kind) { q += " AND kind = ?"; binds.push(kind); }
      q += " ORDER BY created_at DESC";
      const { results } = await env.DB.prepare(q).bind(...binds).all();
      return results;
    },
    campaign: async (_, { id }, { env }) => {
      return await env.DB.prepare("SELECT * FROM campaigns WHERE id = ?").bind(id).first();
    },
    campaignBySlug: async (_, { slug }, { env }) => {
      return await env.DB.prepare("SELECT * FROM campaigns WHERE slug = ?").bind(slug).first();
    },
    targetGroups: async (_, { campaignId }, { env }) => {
      if (campaignId) {
        const { results } = await env.DB.prepare(
          "SELECT * FROM target_groups WHERE campaign_id = ? ORDER BY created_at DESC"
        ).bind(campaignId).all();
        return results;
      }
      const { results } = await env.DB.prepare("SELECT * FROM target_groups ORDER BY created_at DESC").all();
      return results;
    },
    targetGroup: async (_, { id }, { env }) => {
      return await env.DB.prepare("SELECT * FROM target_groups WHERE id = ?").bind(id).first();
    },
    jobTemplates: async (_, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM job_templates ORDER BY created_at DESC").all();
      return results;
    },
    jobTemplate: async (_, { id }, { env }) => {
      return await env.DB.prepare("SELECT * FROM job_templates WHERE id = ?").bind(id).first();
    },
    playbooks: async (_, { campaignId }, { env }) => {
      if (campaignId) {
        const { results } = await env.DB.prepare(
          "SELECT * FROM playbooks WHERE campaign_id = ? ORDER BY created_at DESC"
        ).bind(campaignId).all();
        return results;
      }
      const { results } = await env.DB.prepare("SELECT * FROM playbooks ORDER BY created_at DESC").all();
      return results;
    },
    playbook: async (_, { id }, { env }) => {
      return await env.DB.prepare("SELECT * FROM playbooks WHERE id = ?").bind(id).first();
    },
    apiTokens: async (_, __, ctx) => {
      requireRole(ctx, 'admin');
      const { results } = await ctx.env.DB.prepare(
        "SELECT id, user_id, name, role, revoked, last_used_at, created_at FROM api_tokens ORDER BY created_at DESC"
      ).all();
      return results;
    }
  },

  Mutation: {
    createUser: async (_, { username, number_id, first_name, last_name }, { env }) => {
      const id = crypto.randomUUID();
      return await env.DB.prepare(
        `INSERT INTO users (id, username, number_id, first_name, last_name)
         VALUES (?, ?, ?, ?, ?)
         RETURNING *`
      ).bind(id, username, number_id ? Number(number_id) : null, first_name || null, last_name || null).first();
    },
    updateUser: async (_, { id, username, number_id, first_name, last_name }, { env }) => {
      return await env.DB.prepare(
        `UPDATE users
         SET username = COALESCE(?, username),
             number_id = COALESCE(?, number_id),
             first_name = COALESCE(?, first_name),
             last_name = COALESCE(?, last_name),
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?
         RETURNING *`
      ).bind(username || null, number_id ? Number(number_id) : null, first_name || null, last_name || null, id).first();
    },
    deleteUser: async (_, { id }, { env }) => {
      const res = await env.DB.prepare("DELETE FROM users WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },
    createCompany: async (_, { input }, { env }) => {
      const id = crypto.randomUUID();
      const { name, slug, description, owner_user_id, data } = input;
      return await env.DB.prepare(
        `INSERT INTO companies (id, name, slug, description, owner_user_id, data)
         VALUES (?, ?, ?, ?, ?, ?)
         RETURNING *`
      ).bind(id, name, slug || null, description || null, owner_user_id || null, JSON.stringify(data || {})).first();
    },
    updateCompany: async (_, { id, input }, { env }) => {
      const { name, slug, description, owner_user_id, data } = input;
      // SQLite patch to merge data
      let patchQuery = "";
      const binds = [name || null, slug || null, description || null, owner_user_id || null];
      
      if (data) {
        patchQuery = ", data = json_patch(COALESCE(data, '{}'), ?)";
        binds.push(JSON.stringify(data));
      }
      
      binds.push(id);
      
      return await env.DB.prepare(
        `UPDATE companies
         SET name = COALESCE(?, name),
             slug = COALESCE(?, slug),
             description = COALESCE(?, description),
             owner_user_id = COALESCE(?, owner_user_id)
             ${patchQuery},
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?
         RETURNING *`
      ).bind(...binds).first();
    },
    deleteCompany: async (_, { id }, { env }) => {
      const res = await env.DB.prepare("DELETE FROM companies WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },
    createDomain: async (_, { input }, { env }) => {
      const { company_id, host, canonical_url, data } = input;
      const existing = await env.DB.prepare(
        "SELECT * FROM domains WHERE company_id = ? AND lower(host) = lower(?)"
      ).bind(company_id, host).first();
      
      if (existing) {
        return existing;
      }

      const id = crypto.randomUUID();
      return await env.DB.prepare(
        `INSERT INTO domains (id, company_id, host, canonical_url, data)
         VALUES (?, ?, ?, ?, ?)
         RETURNING *`
      ).bind(id, company_id, host, canonical_url || null, JSON.stringify(data || {})).first();
    },
    updateDomain: async (_, { id, input }, { env }) => {
      const { company_id, host, canonical_url, data } = input;
      let patchQuery = "";
      const binds = [company_id || null, host || null, canonical_url || null];
      
      if (data) {
        patchQuery = ", data = json_patch(COALESCE(data, '{}'), ?)";
        binds.push(JSON.stringify(data));
      }
      
      binds.push(id);
      
      return await env.DB.prepare(
        `UPDATE domains
         SET company_id = COALESCE(?, company_id),
             host = COALESCE(?, host),
             canonical_url = COALESCE(?, canonical_url)
             ${patchQuery},
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?
         RETURNING *`
      ).bind(...binds).first();
    },
    deleteDomain: async (_, { id }, { env }) => {
      const res = await env.DB.prepare("DELETE FROM domains WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },
    createPeople: async (_, { input }, { env }) => {
      const id = crypto.randomUUID();
      const { company_id, given_name, family_name, emails, phones, notes, data } = input;
      return await env.DB.prepare(
        `INSERT INTO people (id, company_id, given_name, family_name, emails, phones, notes, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING *`
      ).bind(
        id,
        company_id,
        given_name || null,
        family_name || null,
        JSON.stringify(emails || []),
        JSON.stringify(phones || []),
        notes || null,
        JSON.stringify(data || {})
      ).first();
    },
    updatePeople: async (_, { id, input }, { env }) => {
      const { company_id, given_name, family_name, emails, phones, notes, data } = input;
      
      let patchQuery = "";
      const binds = [company_id || null, given_name || null, family_name || null];
      
      if (emails) {
        patchQuery += ", emails = ?";
        binds.push(JSON.stringify(emails));
      } else {
        patchQuery += ", emails = COALESCE(?, emails)";
        binds.push(null);
      }
      
      if (phones) {
        patchQuery += ", phones = ?";
        binds.push(JSON.stringify(phones));
      } else {
        patchQuery += ", phones = COALESCE(?, phones)";
        binds.push(null);
      }
      
      binds.push(notes || null);
      
      if (data) {
        patchQuery += ", data = json_patch(COALESCE(data, '{}'), ?)";
        binds.push(JSON.stringify(data));
      }
      
      binds.push(id);
      
      return await env.DB.prepare(
        `UPDATE people
         SET company_id = COALESCE(?, company_id),
             given_name = COALESCE(?, given_name),
             family_name = COALESCE(?, family_name)
             ${patchQuery},
             notes = COALESCE(?, notes)
         WHERE id = ?
         RETURNING *`
      ).bind(...binds).first();
    },
    deletePeople: async (_, { id }, { env }) => {
      const res = await env.DB.prepare("DELETE FROM people WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },

    // Scanner mutations
    updateHttpxResults: async (_, { domain, results }, { env }) => {
      const domRow = await env.DB.prepare("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      const compRow = await env.DB.prepare("SELECT id FROM companies WHERE slug = ? OR lower(name) = lower(?) LIMIT 1").bind(domain, domain).first();
      const companyId = domRow ? domRow.company_id : (compRow ? compRow.id : null);

      for (const result of results) {
        const raw_url = result.url || '';
        const input_host = result.input || '';
        let host = '';
        if (input_host) {
          host = input_host.trim().toLowerCase();
        } else {
          host = raw_url.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].trim().toLowerCase();
        }
        if (!host) continue;

        const patch = JSON.stringify({
          title: result.title || '',
          webserver: result.webserver || '',
          status_code: result.status_code || 0,
          headers: result.header || {},
          tech: result.tech || [],
          last_scan: new Date().toISOString()
        });

        const existing = await env.DB.prepare("SELECT id FROM domains WHERE lower(host) = lower(?)").bind(host).first();
        if (existing) {
          await env.DB.prepare(
            `UPDATE domains
             SET data = json_patch(COALESCE(data, '{}'), ?),
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE lower(host) = lower(?)`
          ).bind(patch, host).run();
        } else if (companyId) {
          const id = crypto.randomUUID();
          await env.DB.prepare(
            `INSERT INTO domains (id, company_id, host, canonical_url, data)
             VALUES (?, ?, ?, ?, ?)`
          ).bind(id, companyId, host, raw_url || `https://${host}`, patch).run();
        }
      }
      return true;
    },
    updatePortScanResults: async (_, { domain, ports, ips }, { env }) => {
      // Find company id for the domain
      const domRow = await env.DB.prepare("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      if (!domRow) return false;
      const companyId = domRow.company_id;

      const patch = JSON.stringify({
        ports: ports || [],
        ips: ips || [],
        last_port_scan: new Date().toISOString(),
        phase: '3'
      });

      await env.DB.prepare(
        `UPDATE companies
         SET data = json_patch(COALESCE(data, '{}'), ?),
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?`
      ).bind(patch, companyId).run();
      return true;
    },
    updateKatanaResults: async (_, { domain, results }, { env }) => {
      // Find company id for the domain
      const domRow = await env.DB.prepare("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      if (!domRow) return false;
      const companyId = domRow.company_id;

      const statements = [];
      for (const result of results) {
        const host = result.host || '';
        const patch = JSON.stringify({
          katana: {
            files: result.files || [],
            urls: result.urls || [],
            params: result.params || [],
            last_scan: new Date().toISOString()
          }
        });
        
        statements.push(
          env.DB.prepare(
            `UPDATE domains
             SET data = json_patch(COALESCE(data, '{}'), ?),
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE lower(host) = lower(?)`
          ).bind(patch, host)
        );
      }

      // Update company phase to 4
      statements.push(
        env.DB.prepare(
          `UPDATE companies
           SET data = json_patch(COALESCE(data, '{}'), '{"phase": "4"}'),
               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
           WHERE id = ?`
        ).bind(companyId)
      );

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    updateNucleiResults: async (_, { domain, results }, { env }) => {
      // Find company id for the domain
      const domRow = await env.DB.prepare("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      if (!domRow) return false;
      const companyId = domRow.company_id;

      const statements = [];
      // results is an object mapping subdomain URL -> array of findings/vulns
      for (const [url, vulns] of Object.entries(results || {})) {
        const patch = JSON.stringify({
          nuclei: vulns || [],
          last_scan: new Date().toISOString()
        });
        
        statements.push(
          env.DB.prepare(
            `UPDATE domains
             SET data = json_patch(COALESCE(data, '{}'), ?),
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE lower(canonical_url) = lower(?) OR lower(host) = lower(?)`
          ).bind(patch, url, url.replace(/^https?:\/\//, '').replace(/\/.*$/, ''))
        );
      }

      // Update company phase to 5
      statements.push(
        env.DB.prepare(
          `UPDATE companies
           SET data = json_patch(COALESCE(data, '{}'), '{"phase": "5"}'),
               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
           WHERE id = ?`
        ).bind(companyId)
      );

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    updateJsResults: async (_, { domain, results }, { env }) => {
      const domRow = await env.DB.prepare("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      if (!domRow) return false;
      const companyId = domRow.company_id;

      const statements = [];
      for (const result of results) {
        const host = result.host || domain;
        const patch = JSON.stringify({
          js_findings: result.findings || [],
          js_endpoints: result.endpoints || [],
          last_js_scan: new Date().toISOString()
        });

        statements.push(
          env.DB.prepare(
            `UPDATE domains
             SET data = json_patch(COALESCE(data, '{}'), ?),
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE lower(host) = lower(?)`
          ).bind(patch, host)
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    updateExposureResults: async (_, { domain, results }, { env }) => {
      const domRow = await env.DB.prepare("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      if (!domRow) return false;
      const companyId = domRow.company_id;

      const statements = [];
      for (const result of results) {
        const host = result.host || domain;
        const patch = JSON.stringify({
          exposures: result.exposures || [],
          last_exposure_scan: new Date().toISOString()
        });

        statements.push(
          env.DB.prepare(
            `UPDATE domains
             SET data = json_patch(COALESCE(data, '{}'), ?),
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE lower(host) = lower(?)`
          ).bind(patch, host)
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    updateTakeoverResults: async (_, { domain, results }, { env }) => {
      const domRow = await env.DB.prepare("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      if (!domRow) return false;

      const statements = [];
      for (const result of results) {
        const host = result.host || domain;
        const patch = JSON.stringify({
          takeover: result.takeover || null,
          last_takeover_scan: new Date().toISOString()
        });

        statements.push(
          env.DB.prepare(
            `UPDATE domains
             SET data = json_patch(COALESCE(data, '{}'), ?),
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE lower(host) = lower(?)`
          ).bind(patch, host)
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    createFindingsBatch: async (_, { domain, findings }, { env }) => {
      const domRow = await env.DB.prepare("SELECT id, company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      const domainId = domRow ? domRow.id : null;
      const companyId = domRow ? domRow.company_id : null;

      const statements = [];
      for (const f of findings) {
        const id = f.id || crypto.randomUUID();
        statements.push(
          env.DB.prepare(`
            INSERT OR REPLACE INTO findings (id, domain_id, company_id, tool, severity, vuln_type, title, url, description, evidence, poc, cve, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            id, domainId, companyId,
            f.tool, f.severity, f.vuln_type, f.title,
            f.url || null, f.description || null, f.evidence || null,
            f.poc || null, f.cve || null, f.status || 'open'
          )
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    createEndpointsBatch: async (_, { domain, endpoints }, { env }) => {
      const domRow = await env.DB.prepare("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      const domainId = domRow ? domRow.id : null;

      const statements = [];
      for (const ep of endpoints) {
        const id = ep.id || crypto.randomUUID();
        const params = Array.isArray(ep.params) ? JSON.stringify(ep.params) : (typeof ep.params === 'string' ? ep.params : '[]');
        statements.push(
          env.DB.prepare(`
            INSERT OR REPLACE INTO endpoints (id, domain_id, url, method, params, status_code, content_type, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            id, domainId, ep.url, ep.method || 'GET',
            params, ep.status_code || null, ep.content_type || null, ep.source || 'crawler'
          )
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    createSecretsBatch: async (_, { domain, secrets }, { env }) => {
      const domRow = await env.DB.prepare("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      const domainId = domRow ? domRow.id : null;

      const statements = [];
      for (const s of secrets) {
        const id = s.id || crypto.randomUUID();
        statements.push(
          env.DB.prepare(`
            INSERT OR REPLACE INTO secrets (id, domain_id, rule_name, secret_type, match_snippet, file_url, severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            id, domainId, s.rule_name, s.secret_type,
            s.match_snippet, s.file_url || null, s.severity || 'high', s.status || 'open'
          )
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },
    createNetworkServicesBatch: async (_, { domain, services }, { env }) => {
      const domRow = await env.DB.prepare("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1").bind(domain).first();
      const domainId = domRow ? domRow.id : null;

      const statements = [];
      for (const s of services) {
        const id = s.id || crypto.randomUUID();
        statements.push(
          env.DB.prepare(`
            INSERT OR REPLACE INTO network_services (id, domain_id, ip, port, protocol, service, product, version, banner)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            id, domainId, s.ip, Number(s.port), s.protocol || 'tcp',
            s.service || null, s.product || null, s.version || null, s.banner || null
          )
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return true;
    },

    // ---- Team workflows: API tokens ----
    createApiToken: async (_, { userId, name, role }, ctx) => {
      // Bootstrap: allowed without auth until AUTH_ENFORCED=true; then admin-only.
      requireRole(ctx, 'admin');
      const { env, auth } = ctx;
      const tokenRole = role || 'member';
      if (!TOKEN_ROLE_RANK[tokenRole]) {
        throw new GraphQLError(`Invalid role '${tokenRole}'`, { extensions: { code: 'BAD_USER_INPUT' } });
      }
      const uid = userId || auth?.userId || null;
      // 32 random bytes, hex-encoded, prefixed so it's recognizable in configs.
      const rawBytes = crypto.getRandomValues(new Uint8Array(32));
      const raw = 'chk_' + [...rawBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
      const hash = await sha256hex(raw);
      const id = crypto.randomUUID();
      const row = await env.DB.prepare(
        `INSERT INTO api_tokens (id, user_id, name, token_hash, role)
         VALUES (?, ?, ?, ?, ?)
         RETURNING id, user_id, name, role, revoked, last_used_at, created_at`
      ).bind(id, uid, name, hash, tokenRole).first();
      return { ...row, token: raw }; // plaintext returned only here
    },
    revokeApiToken: async (_, { id }, ctx) => {
      requireRole(ctx, 'admin');
      const res = await ctx.env.DB.prepare("UPDATE api_tokens SET revoked = 1 WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },

    // ---- Campaigns ----
    createCampaign: async (_, { input }, ctx) => {
      requireRole(ctx, 'member');
      const { env, auth } = ctx;
      const id = crypto.randomUUID();
      const owner = input.owner_user_id || auth?.userId || null;
      const row = await env.DB.prepare(
        `INSERT INTO campaigns (id, name, slug, owner_user_id, company_id, kind, status, authorized, scope, description, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING *`
      ).bind(
        id, input.name, input.slug || slugify(input.name), owner, input.company_id || null,
        input.kind || 'engagement', input.status || 'prospect', input.authorized ? 1 : 0,
        JSON.stringify(input.scope || {}), input.description || null, JSON.stringify(input.data || {})
      ).first();
      // Owner becomes the campaign lead.
      if (owner) {
        await env.DB.prepare(
          "INSERT OR IGNORE INTO campaign_members (campaign_id, user_id, role) VALUES (?, ?, 'lead')"
        ).bind(id, owner).run();
      }
      return row;
    },
    updateCampaign: async (_, { id, input }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM campaigns WHERE id = ?").bind(id).first();
      if (!existing) throw new GraphQLError('Campaign not found', { extensions: { code: 'NOT_FOUND' } });
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      let patch = "";
      const binds = [
        input.name ?? null, input.slug ?? null, input.company_id ?? null,
        input.kind ?? null, input.status ?? null,
        (input.authorized === undefined || input.authorized === null) ? null : (input.authorized ? 1 : 0),
        input.description ?? null,
      ];
      if (input.scope) { patch += ", scope = json_patch(COALESCE(scope,'{}'), ?)"; binds.push(JSON.stringify(input.scope)); }
      if (input.data) { patch += ", data = json_patch(COALESCE(data,'{}'), ?)"; binds.push(JSON.stringify(input.data)); }
      binds.push(id);
      return await ctx.env.DB.prepare(
        `UPDATE campaigns SET
           name = COALESCE(?, name), slug = COALESCE(?, slug), company_id = COALESCE(?, company_id),
           kind = COALESCE(?, kind), status = COALESCE(?, status), authorized = COALESCE(?, authorized),
           description = COALESCE(?, description)${patch},
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ? RETURNING *`
      ).bind(...binds).first();
    },
    deleteCampaign: async (_, { id }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM campaigns WHERE id = ?").bind(id).first();
      if (!existing) return false;
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      const res = await ctx.env.DB.prepare("DELETE FROM campaigns WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },
    setCampaignStatus: async (_, { id, status }, ctx) => {
      requireRole(ctx, 'member');
      return await ctx.env.DB.prepare(
        "UPDATE campaigns SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ? RETURNING *"
      ).bind(status, id).first();
    },
    addCampaignMember: async (_, { campaignId, userId, role }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM campaigns WHERE id = ?").bind(campaignId).first();
      if (!existing) throw new GraphQLError('Campaign not found', { extensions: { code: 'NOT_FOUND' } });
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      return await ctx.env.DB.prepare(
        `INSERT INTO campaign_members (campaign_id, user_id, role) VALUES (?, ?, ?)
         ON CONFLICT(campaign_id, user_id) DO UPDATE SET role = excluded.role
         RETURNING *`
      ).bind(campaignId, userId, role || 'member').first();
    },
    removeCampaignMember: async (_, { campaignId, userId }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM campaigns WHERE id = ?").bind(campaignId).first();
      if (!existing) return false;
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      const res = await ctx.env.DB.prepare(
        "DELETE FROM campaign_members WHERE campaign_id = ? AND user_id = ? RETURNING user_id"
      ).bind(campaignId, userId).first();
      return !!res;
    },

    // ---- Target groups ----
    createTargetGroup: async (_, { input }, ctx) => {
      requireRole(ctx, 'member');
      const id = crypto.randomUUID();
      const owner = input.owner_user_id || ctx.auth?.userId || null;
      return await ctx.env.DB.prepare(
        `INSERT INTO target_groups (id, campaign_id, name, owner_user_id, visibility, description, data)
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`
      ).bind(id, input.campaign_id || null, input.name, owner, input.visibility || 'team',
             input.description || null, JSON.stringify(input.data || {})).first();
    },
    updateTargetGroup: async (_, { id, input }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM target_groups WHERE id = ?").bind(id).first();
      if (!existing) throw new GraphQLError('Target group not found', { extensions: { code: 'NOT_FOUND' } });
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      let patch = "";
      const binds = [input.name ?? null, input.campaign_id ?? null, input.visibility ?? null, input.description ?? null];
      if (input.data) { patch += ", data = json_patch(COALESCE(data,'{}'), ?)"; binds.push(JSON.stringify(input.data)); }
      binds.push(id);
      return await ctx.env.DB.prepare(
        `UPDATE target_groups SET
           name = COALESCE(?, name), campaign_id = COALESCE(?, campaign_id),
           visibility = COALESCE(?, visibility), description = COALESCE(?, description)${patch},
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ? RETURNING *`
      ).bind(...binds).first();
    },
    deleteTargetGroup: async (_, { id }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM target_groups WHERE id = ?").bind(id).first();
      if (!existing) return false;
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      const res = await ctx.env.DB.prepare("DELETE FROM target_groups WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },
    addDomainToGroup: async (_, { groupId, domainId }, ctx) => {
      requireRole(ctx, 'member');
      await ctx.env.DB.prepare(
        "INSERT OR IGNORE INTO target_group_members (group_id, domain_id, added_by) VALUES (?, ?, ?)"
      ).bind(groupId, domainId, ctx.auth?.userId || null).run();
      return true;
    },
    removeDomainFromGroup: async (_, { groupId, domainId }, ctx) => {
      requireRole(ctx, 'member');
      const res = await ctx.env.DB.prepare(
        "DELETE FROM target_group_members WHERE group_id = ? AND domain_id = ? RETURNING domain_id"
      ).bind(groupId, domainId).first();
      return !!res;
    },

    // ---- Job templates ----
    createJobTemplate: async (_, { input }, ctx) => {
      requireRole(ctx, 'member');
      const id = crypto.randomUUID();
      const owner = ctx.auth?.userId || null;
      return await ctx.env.DB.prepare(
        `INSERT INTO job_templates (id, name, slug, owner_user_id, visibility, command_template, phases, default_flags, runner, description, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
      ).bind(
        id, input.name, input.slug || slugify(input.name), owner, input.visibility || 'team',
        input.command_template, JSON.stringify(input.phases || []), JSON.stringify(input.default_flags || {}),
        input.runner || 'default', input.description || null, JSON.stringify(input.data || {})
      ).first();
    },
    updateJobTemplate: async (_, { id, input }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM job_templates WHERE id = ?").bind(id).first();
      if (!existing) throw new GraphQLError('Job template not found', { extensions: { code: 'NOT_FOUND' } });
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      let patch = "";
      const binds = [input.name ?? null, input.slug ?? null, input.visibility ?? null,
                     input.command_template ?? null, input.runner ?? null, input.description ?? null];
      if (input.phases) { patch += ", phases = ?"; binds.push(JSON.stringify(input.phases)); }
      if (input.default_flags) { patch += ", default_flags = json_patch(COALESCE(default_flags,'{}'), ?)"; binds.push(JSON.stringify(input.default_flags)); }
      if (input.data) { patch += ", data = json_patch(COALESCE(data,'{}'), ?)"; binds.push(JSON.stringify(input.data)); }
      binds.push(id);
      return await ctx.env.DB.prepare(
        `UPDATE job_templates SET
           name = COALESCE(?, name), slug = COALESCE(?, slug), visibility = COALESCE(?, visibility),
           command_template = COALESCE(?, command_template), runner = COALESCE(?, runner),
           description = COALESCE(?, description)${patch},
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ? RETURNING *`
      ).bind(...binds).first();
    },
    deleteJobTemplate: async (_, { id }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM job_templates WHERE id = ?").bind(id).first();
      if (!existing) return false;
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      const res = await ctx.env.DB.prepare("DELETE FROM job_templates WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },

    // ---- Playbooks ----
    createPlaybook: async (_, { input }, ctx) => {
      requireRole(ctx, 'member');
      const id = crypto.randomUUID();
      const owner = ctx.auth?.userId || null;
      return await ctx.env.DB.prepare(
        `INSERT INTO playbooks (id, name, slug, campaign_id, owner_user_id, visibility, description, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
      ).bind(id, input.name, input.slug || slugify(input.name), input.campaign_id || null, owner,
             input.visibility || 'team', input.description || null, JSON.stringify(input.data || {})).first();
    },
    updatePlaybook: async (_, { id, input }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM playbooks WHERE id = ?").bind(id).first();
      if (!existing) throw new GraphQLError('Playbook not found', { extensions: { code: 'NOT_FOUND' } });
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      let patch = "";
      const binds = [input.name ?? null, input.slug ?? null, input.campaign_id ?? null, input.visibility ?? null, input.description ?? null];
      if (input.data) { patch += ", data = json_patch(COALESCE(data,'{}'), ?)"; binds.push(JSON.stringify(input.data)); }
      binds.push(id);
      return await ctx.env.DB.prepare(
        `UPDATE playbooks SET
           name = COALESCE(?, name), slug = COALESCE(?, slug), campaign_id = COALESCE(?, campaign_id),
           visibility = COALESCE(?, visibility), description = COALESCE(?, description)${patch},
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ? RETURNING *`
      ).bind(...binds).first();
    },
    deletePlaybook: async (_, { id }, ctx) => {
      requireRole(ctx, 'member');
      const existing = await ctx.env.DB.prepare("SELECT owner_user_id FROM playbooks WHERE id = ?").bind(id).first();
      if (!existing) return false;
      requireOwnerOrAdmin(ctx, existing.owner_user_id);
      const res = await ctx.env.DB.prepare("DELETE FROM playbooks WHERE id = ? RETURNING id").bind(id).first();
      return !!res;
    },
    setPlaybookSteps: async (_, { playbookId, steps }, ctx) => {
      requireRole(ctx, 'member');
      const pb = await ctx.env.DB.prepare("SELECT * FROM playbooks WHERE id = ?").bind(playbookId).first();
      if (!pb) throw new GraphQLError('Playbook not found', { extensions: { code: 'NOT_FOUND' } });
      requireOwnerOrAdmin(ctx, pb.owner_user_id);
      const statements = [ctx.env.DB.prepare("DELETE FROM playbook_steps WHERE playbook_id = ?").bind(playbookId)];
      for (const s of steps) {
        statements.push(ctx.env.DB.prepare(
          `INSERT INTO playbook_steps (id, playbook_id, step_order, template_id, phase, params)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(crypto.randomUUID(), playbookId, Number(s.step_order), s.template_id || null,
               s.phase || null, JSON.stringify(s.params || {})));
      }
      await ctx.env.DB.batch(statements);
      return pb;
    },
    bindPlaybookToTarget: async (_, { playbookId, domainId, groupId }, ctx) => {
      requireRole(ctx, 'member');
      if (!domainId && !groupId) {
        throw new GraphQLError('Provide domainId or groupId', { extensions: { code: 'BAD_USER_INPUT' } });
      }
      await ctx.env.DB.prepare(
        "INSERT INTO target_playbooks (id, playbook_id, domain_id, group_id, created_by) VALUES (?, ?, ?, ?, ?)"
      ).bind(crypto.randomUUID(), playbookId, domainId || null, groupId || null, ctx.auth?.userId || null).run();
      return true;
    },

    // ---- Execution: expand templates/playbooks into scan_jobs ----
    runTemplate: async (_, { templateId, target, runner, senderId }, ctx) => {
      requireRole(ctx, 'member');
      const tpl = await ctx.env.DB.prepare("SELECT * FROM job_templates WHERE id = ?").bind(templateId).first();
      if (!tpl) throw new GraphQLError('Job template not found', { extensions: { code: 'NOT_FOUND' } });
      const safe = assertSafeTarget(target);
      const command = expandCommandTemplate(tpl.command_template, safe, senderId != null ? String(senderId) : '');
      const jobId = await queueJob(ctx.env, command, safe, runner || tpl.runner || 'default');
      return { jobIds: [jobId], count: 1 };
    },
    runPlaybook: async (_, { playbookId, target, groupId, runner, senderId }, ctx) => {
      requireRole(ctx, 'member');
      const pb = await ctx.env.DB.prepare("SELECT * FROM playbooks WHERE id = ?").bind(playbookId).first();
      if (!pb) throw new GraphQLError('Playbook not found', { extensions: { code: 'NOT_FOUND' } });

      // Authorization gate: a playbook tied to a campaign only runs once that
      // campaign is explicitly marked authorized (signed/in-scope).
      if (pb.campaign_id) {
        const camp = await ctx.env.DB.prepare("SELECT authorized FROM campaigns WHERE id = ?").bind(pb.campaign_id).first();
        if (camp && !camp.authorized) {
          throw new GraphQLError('Campaign is not marked authorized; refuse to launch scans', { extensions: { code: 'FORBIDDEN' } });
        }
      }

      // Resolve the set of targets.
      let targets = [];
      if (target) {
        targets = [assertSafeTarget(target)];
      } else if (groupId) {
        const { results } = await ctx.env.DB.prepare(
          `SELECT d.host FROM target_group_members m JOIN domains d ON d.id = m.domain_id WHERE m.group_id = ?`
        ).bind(groupId).all();
        targets = results.map((r) => r.host).filter(Boolean).map(assertSafeTarget);
      } else {
        // Fall back to the playbook's bound targets (per-target playbooks).
        const { results: boundDomains } = await ctx.env.DB.prepare(
          `SELECT d.host FROM target_playbooks tp JOIN domains d ON d.id = tp.domain_id WHERE tp.playbook_id = ? AND tp.domain_id IS NOT NULL`
        ).bind(playbookId).all();
        const { results: boundGroupDomains } = await ctx.env.DB.prepare(
          `SELECT DISTINCT d.host FROM target_playbooks tp
             JOIN target_group_members m ON m.group_id = tp.group_id
             JOIN domains d ON d.id = m.domain_id
           WHERE tp.playbook_id = ? AND tp.group_id IS NOT NULL`
        ).bind(playbookId).all();
        targets = [...boundDomains, ...boundGroupDomains].map((r) => r.host).filter(Boolean).map(assertSafeTarget);
      }

      if (targets.length === 0) {
        throw new GraphQLError('No targets resolved for this playbook', { extensions: { code: 'BAD_USER_INPUT' } });
      }

      const { results: stepRows } = await ctx.env.DB.prepare(
        "SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_order ASC"
      ).bind(playbookId).all();
      if (stepRows.length === 0) {
        throw new GraphQLError('Playbook has no steps', { extensions: { code: 'BAD_USER_INPUT' } });
      }

      // Pre-load any templates referenced by steps.
      const tplCache = {};
      for (const st of stepRows) {
        if (st.template_id && !tplCache[st.template_id]) {
          tplCache[st.template_id] = await ctx.env.DB.prepare("SELECT * FROM job_templates WHERE id = ?").bind(st.template_id).first();
        }
      }

      const sender = senderId != null ? String(senderId) : '';
      const jobIds = [];
      for (const t of targets) {
        for (const st of stepRows) {
          let command;
          let stepRunner = runner || 'default';
          if (st.template_id && tplCache[st.template_id]) {
            const tpl = tplCache[st.template_id];
            command = expandCommandTemplate(tpl.command_template, t, sender);
            stepRunner = runner || tpl.runner || 'default';
          } else {
            command = commandForPhase(st.phase, t, sender);
          }
          jobIds.push(await queueJob(ctx.env, command, t, stepRunner));
        }
      }
      return { jobIds, count: jobIds.length };
    }
  },

  // Relationship resolvers
  Endpoint: {
    params: (parent) => parseJson(parent.params),
  },
  Company: {
    data: (parent) => parseJson(parent.data),
    domains: async (parent, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM domains WHERE company_id = ?").bind(parent.id).all();
      return results;
    },
    people: async (parent, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM people WHERE company_id = ?").bind(parent.id).all();
      return results;
    },
  },
  Domain: {
    data: (parent) => parseJson(parent.data),
    company: async (parent, __, { env }) => {
      return await env.DB.prepare("SELECT * FROM companies WHERE id = ?").bind(parent.company_id).first();
    },
  },
  People: {
    emails: (parent) => parseJson(parent.emails),
    phones: (parent) => parseJson(parent.phones),
    data: (parent) => parseJson(parent.data),
    company: async (parent, __, { env }) => {
      if (!parent.company_id) return null;
      return await env.DB.prepare("SELECT * FROM companies WHERE id = ?").bind(parent.company_id).first();
    },
    creator: async (parent, __, { env }) => {
      if (!parent.created_by) return null;
      return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(parent.created_by).first();
    },
  },

  // ---- Team-workflow relationship resolvers ----
  ApiToken: {
    revoked: (parent) => !!parent.revoked,
    user: async (parent, __, { env }) => {
      if (!parent.user_id) return null;
      return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(parent.user_id).first();
    },
  },
  Campaign: {
    authorized: (parent) => !!parent.authorized,
    scope: (parent) => parseJson(parent.scope),
    data: (parent) => parseJson(parent.data),
    owner: async (parent, __, { env }) => {
      if (!parent.owner_user_id) return null;
      return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(parent.owner_user_id).first();
    },
    company: async (parent, __, { env }) => {
      if (!parent.company_id) return null;
      return await env.DB.prepare("SELECT * FROM companies WHERE id = ?").bind(parent.company_id).first();
    },
    members: async (parent, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM campaign_members WHERE campaign_id = ?").bind(parent.id).all();
      return results;
    },
    targetGroups: async (parent, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM target_groups WHERE campaign_id = ? ORDER BY created_at DESC").bind(parent.id).all();
      return results;
    },
    playbooks: async (parent, __, { env }) => {
      const { results } = await env.DB.prepare("SELECT * FROM playbooks WHERE campaign_id = ? ORDER BY created_at DESC").bind(parent.id).all();
      return results;
    },
  },
  CampaignMember: {
    user: async (parent, __, { env }) => {
      if (!parent.user_id) return null;
      return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(parent.user_id).first();
    },
  },
  TargetGroup: {
    data: (parent) => parseJson(parent.data),
    domains: async (parent, __, { env }) => {
      const { results } = await env.DB.prepare(
        `SELECT d.* FROM target_group_members m JOIN domains d ON d.id = m.domain_id WHERE m.group_id = ?`
      ).bind(parent.id).all();
      return results;
    },
    campaign: async (parent, __, { env }) => {
      if (!parent.campaign_id) return null;
      return await env.DB.prepare("SELECT * FROM campaigns WHERE id = ?").bind(parent.campaign_id).first();
    },
  },
  JobTemplate: {
    phases: (parent) => parseJsonArray(parent.phases),
    default_flags: (parent) => parseJson(parent.default_flags),
    data: (parent) => parseJson(parent.data),
  },
  Playbook: {
    data: (parent) => parseJson(parent.data),
    steps: async (parent, __, { env }) => {
      const { results } = await env.DB.prepare(
        "SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_order ASC"
      ).bind(parent.id).all();
      return results;
    },
    campaign: async (parent, __, { env }) => {
      if (!parent.campaign_id) return null;
      return await env.DB.prepare("SELECT * FROM campaigns WHERE id = ?").bind(parent.campaign_id).first();
    },
  },
  PlaybookStep: {
    params: (parent) => parseJson(parent.params),
    template: async (parent, __, { env }) => {
      if (!parent.template_id) return null;
      return await env.DB.prepare("SELECT * FROM job_templates WHERE id = ?").bind(parent.template_id).first();
    },
  },
  Subscription: {
    companyUpdated: { subscribe: () => {} },
    domainUpdated: { subscribe: () => {} },
    peopleUpdated: { subscribe: () => {} },
    map: { subscribe: () => {} },
    ongoingRecons: { subscribe: () => {} },
    
    scriptOutput: {
      subscribe: async function* (_, { jobId }, { env }) {
        let lastLen = 0;
        while (true) {
          const job = await env.DB.prepare("SELECT * FROM scan_jobs WHERE id = ?").bind(jobId).first();
          if (!job) {
            yield { scriptOutput: "Job not found" };
            break;
          }
          const stdout = job.stdout || '';
          if (stdout.length > lastLen) {
            const newOutput = stdout.slice(lastLen);
            lastLen = stdout.length;
            yield { scriptOutput: newOutput };
          }
          if (job.status === 'completed' || job.status === 'failed') {
            break;
          }
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }
    }
  }
};

const schema = makeExecutableSchema({ typeDefs, resolvers });

const yoga = createYoga({
  schema,
  landingPage: false,
  graphqlEndpoint: '/graphql',
  // Resolve the caller's API token (if any) into ctx.auth for every operation.
  context: async (initialContext) => {
    const env = initialContext.env;
    const request = initialContext.request;
    const auth = env ? await resolveAuth(env, request) : null;
    return { ...initialContext, env, auth };
  }
});

// ----------------------------------------------------
// Continuous Attack-Surface Monitoring helpers
// ----------------------------------------------------

// Parse a human cadence ("30m", "6h", "2d", or a bare number of minutes)
// into minutes. Returns null if unparseable.
const parseInterval = (raw) => {
  if (!raw) return null;
  const m = String(raw).trim().toLowerCase().match(/^(\d+)\s*(m|min|h|hr|hour|d|day)?s?$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (!n || n <= 0) return null;
  const unit = m[2] || 'm';
  if (unit.startsWith('d')) return n * 1440;
  if (unit.startsWith('h')) return n * 60;
  return n; // minutes
};

const formatInterval = (minutes) => {
  if (minutes % 1440 === 0) return `${minutes / 1440}d`;
  if (minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
};

// Classify a monitor target: IP/CIDR -> network, FQDN -> domain, else company.
const inferTargetType = (target) => {
  const t = (target || '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(t)) return 'network';
  if (/\/\d{1,2}$/.test(t)) return 'network';
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(t)) return 'domain';
  return 'company';
};

// Registrable base (eTLD+1 approximation by last two labels). Note: does not
// special-case multi-part TLDs such as co.uk.
const registrableBase = (host) => {
  const parts = (host || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  return parts.slice(-2).join('.');
};

// Build the cHack.sh CLI command string for a monitored scan. Mirrors the
// interactive triggerScan() command format and always carries --sender-id so
// the runner can route drift alerts back to the monitor owner.
const buildMonitorCommand = (monitor, target) => {
  const t = target || monitor.target;
  const sender = monitor.owner_chat_id;
  switch (monitor.scan_type) {
    case 'recon':   return `-d ${t} --sender-id ${sender}`;
    case 'web':     return `--web ${t} --sender-id ${sender}`;
    case 'network': return `--network ${t} --sender-id ${sender}`;
    case 'infogather':
    default:        return `--info-gather ${t} --sender-id ${sender}`;
  }
};

// ----------------------------------------------------
// Telegram Bot Component (grammY)
// ----------------------------------------------------
let botInstance = null;

const getFlagEmoji = (countryCode) => {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  try {
    return String.fromCodePoint(...codePoints);
  } catch (e) {
    return '🌐';
  }
};



const escapeHtml = (str) => {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

// Render the passive person-OSINT findings stored at people.data.osint (written
// by cHack.sh's run_person_osint). Returns an HTML block, or "" when a person
// has no OSINT results yet. `dataField` is the raw people.data column (string
// or object). `max` caps how many list items are shown before a "+N more".
const formatOsintSummary = (dataField, max = 8) => {
  let data = dataField;
  if (typeof data === 'string') {
    try { data = JSON.parse(data || '{}'); } catch (e) { return ''; }
  }
  const o = data && typeof data === 'object' ? data.osint : null;
  if (!o || typeof o !== 'object') return '';

  const toList = (v) => (Array.isArray(v) ? v.filter((x) => x != null && String(x).length) : []);
  const accounts = toList(o.accounts);
  const breaches = toList(o.breaches);
  const emails = toList(o.emails_found);
  const sources = toList(o.sources);

  if (!accounts.length && !breaches.length && !emails.length && !sources.length) {
    return `\n\n🔎 <b>OSINT:</b> scan ran${o.scanned_at ? ` (${escapeHtml(o.scanned_at)})` : ''}, no public exposure found.`;
  }

  const renderItems = (items) => {
    const shown = items.slice(0, max).map((i) => `   • <code>${escapeHtml(i)}</code>`);
    if (items.length > max) shown.push(`   • <i>+${items.length - max} more</i>`);
    return shown.join('\n');
  };

  let out = `\n\n🔎 <b>OSINT findings</b>`;
  if (o.scanned_at) out += ` <i>(${escapeHtml(o.scanned_at)})</i>`;
  if (sources.length) out += `\n• <b>Sources:</b> ${escapeHtml(sources.join(', '))}`;
  if (accounts.length) out += `\n• <b>Accounts (${accounts.length}):</b>\n${renderItems(accounts)}`;
  if (emails.length) out += `\n• <b>Emails (${emails.length}):</b>\n${renderItems(emails)}`;
  if (breaches.length) out += `\n• <b>⚠️ Breaches (${breaches.length}):</b>\n${renderItems(breaches)}`;
  return out;
};

// Quick flag for the contacts list: did this person's OSINT scan turn up any
// public exposure? Returns '⚠️' when breaches are present, '🔎' for other
// findings, or '' when there was no scan or nothing was found.
const osintBadge = (dataField) => {
  let data = dataField;
  if (typeof data === 'string') {
    try { data = JSON.parse(data || '{}'); } catch (e) { return ''; }
  }
  const o = data && typeof data === 'object' ? data.osint : null;
  if (!o || typeof o !== 'object') return '';
  const n = (v) => (Array.isArray(v) ? v.filter((x) => x != null && String(x).length).length : 0);
  if (n(o.breaches)) return '⚠️';
  if (n(o.accounts) || n(o.emails_found)) return '🔎';
  return '';
};

// ===========================================================================
// RBAC & Audit helpers (role-based access and audit controls)
// ===========================================================================

// Global role hierarchy. Higher rank = more privilege. "superadmin" is granted
// out-of-band via the ADMIN_IDS secret and is never stored in the DB.
const ROLE_RANK = { pending: 0, viewer: 1, operator: 2, admin: 3, superadmin: 4 };
const roleRank = (role) => ROLE_RANK[role] ?? 0;

const parseAdminIds = (env) => (env.ADMIN_IDS || "")
  .split(",")
  .map((id) => Number(String(id).trim()))
  .filter((id) => Number.isFinite(id) && id !== 0);

// Resolve the acting user into an authorization context. Pure read; never
// mutates. `legacyOpen` reproduces the pre-RBAC behaviour: when no ADMIN_IDS
// are configured the bot is wide open and every caller is treated as admin, so
// existing single-tenant deployments keep working unchanged.
const resolveActor = async (env, from) => {
  const numberId = from?.id || 0;
  const adminIds = parseAdminIds(env);
  const legacyOpen = adminIds.length === 0;
  const isSuperadmin = adminIds.includes(numberId);

  let user = null;
  try {
    user = await env.DB.prepare(
      "SELECT id, username, role FROM users WHERE number_id = ?"
    ).bind(numberId).first();
  } catch (_) { /* table may be mid-migration */ }

  let memberships = [];
  if (user?.id) {
    try {
      const res = await env.DB.prepare(
        "SELECT company_id, role FROM team_members WHERE user_id = ?"
      ).bind(user.id).all();
      memberships = res?.results || [];
    } catch (_) { /* team_members may not exist yet */ }
  }

  // Effective global role. Superadmins (ADMIN_IDS) always win. When no ADMIN_IDS
  // are configured the deployment is single-tenant/legacy and the sole operator
  // is treated as a superadmin, preserving pre-RBAC behaviour (including reset).
  let role = user?.role || 'pending';
  const effectiveSuper = isSuperadmin || legacyOpen;
  if (effectiveSuper) role = 'superadmin';

  const teamRoleFor = (companyId) => {
    const m = memberships.find((x) => x.company_id === companyId);
    return m ? m.role : null;
  };

  return {
    numberId,
    userId: user?.id || null,
    username: user?.username || (from?.username ? `@${from.username}` : `user_${numberId}`),
    role,
    rank: roleRank(role),
    isSuperadmin: effectiveSuper,
    legacyOpen,
    memberships,
    teamRoleFor,
    hasGlobal: (min) => roleRank(role) >= roleRank(min),
  };
};

// Append-only audit write. Best-effort: a logging failure must never block or
// crash the action being logged. Callable from both bot and runner contexts.
const auditLog = async (env, entry) => {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_log
         (id, actor_user_id, actor_number_id, actor_label, source, action,
          decision, target_type, target, company_id, detail)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      crypto.randomUUID(),
      entry.actor_user_id || null,
      entry.actor_number_id || 0,
      entry.actor_label || null,
      entry.source || 'telegram',
      entry.action,
      entry.decision || 'allow',
      entry.target_type || null,
      entry.target || null,
      entry.company_id || null,
      JSON.stringify(entry.detail || {})
    ).run();
  } catch (err) {
    console.error("audit_log write failed:", err.message);
  }
};

// Per-user/team target-scope check. Returns { allowed, companyId, reason }.
// Policy:
//   - viewer/pending: never allowed to scan.
//   - admin/superadmin (global): may scan any target.
//   - operator (global): may scan a target whose company they belong to, or a
//     target not yet claimed by any company (first scan claims nothing by
//     itself, but is permitted so a team can onboard new in-scope assets).
//   - a target belonging to a company the operator is NOT a member of is denied.
const checkScanScope = async (env, actor, targetValue) => {
  if (!actor.hasGlobal('operator')) {
    return { allowed: false, companyId: null, reason: 'insufficient-role' };
  }
  if (actor.hasGlobal('admin')) {
    // Still resolve company for attribution, but never block.
    const companyId = await resolveTargetCompany(env, targetValue);
    return { allowed: true, companyId, reason: 'admin-bypass' };
  }
  // operator: enforce team scope.
  const companyId = await resolveTargetCompany(env, targetValue);
  if (!companyId) {
    return { allowed: true, companyId: null, reason: 'unclaimed-target' };
  }
  const member = actor.memberships.some((m) => m.company_id === companyId);
  return member
    ? { allowed: true, companyId, reason: 'team-member' }
    : { allowed: false, companyId, reason: 'out-of-scope' };
};

// Best-effort resolution of a scan target to its owning company. Matches an
// exact domain host first, then its registrable parent (sub.example.com ->
// example.com), then a company name/slug. Returns a company id or null.
const resolveTargetCompany = async (env, value) => {
  if (!value) return null;
  const v = String(value).trim().toLowerCase();
  try {
    const dom = await env.DB.prepare(
      "SELECT company_id FROM domains WHERE lower(host) = ? LIMIT 1"
    ).bind(v).first();
    if (dom?.company_id) return dom.company_id;

    const parts = v.split('.');
    if (parts.length > 2) {
      const parent = parts.slice(-2).join('.');
      const pdom = await env.DB.prepare(
        "SELECT company_id FROM domains WHERE lower(host) = ? LIMIT 1"
      ).bind(parent).first();
      if (pdom?.company_id) return pdom.company_id;
    }

    const comp = await env.DB.prepare(
      "SELECT id FROM companies WHERE lower(name) = ? OR lower(slug) = ? LIMIT 1"
    ).bind(v, v).first();
    if (comp?.id) return comp.id;
  } catch (_) { /* best effort */ }
  return null;
};

const createMainMenu = async (ctx, env) => {
  const currentRunner = ctx.session?.selected_runner || 'default';
  let runnerStatusText = `⚙️ ${currentRunner}`;

  try {
    const cutoff = Math.floor(Date.now() / 1000) - 60;
    const activeRunner = await env.DB.prepare(
      "SELECT name, ip, country FROM runners WHERE name = ? AND last_seen >= ?"
    ).bind(currentRunner, cutoff).first();

    if (activeRunner) {
      const flag = getFlagEmoji(activeRunner.country);
      runnerStatusText = `🟢 ${flag} ${activeRunner.name}`;
    } else {
      const lastKnown = await env.DB.prepare(
        "SELECT ip, country FROM runners WHERE name = ?"
      ).bind(currentRunner).first();
      if (lastKnown) {
        const flag = getFlagEmoji(lastKnown.country);
        runnerStatusText = `🔴 ${flag} ${currentRunner}`;
      } else {
        runnerStatusText = `🔴 ${currentRunner}`;
      }
    }
  } catch (err) {
    console.error("D1 error in createMainMenu:", err.message);
  }

  // Role-aware menu: everyone admitted gets the operational buttons; the
  // destructive admin-only control (Reset DB) is shown only to admins. Per-action
  // role/scope checks still apply when a button is tapped.
  const isAdmin = !!(ctx.actor && typeof ctx.actor.hasGlobal === 'function' && ctx.actor.hasGlobal('admin'));

  const keyboard = [
    [
      { text: "🚀 Launch Scan", callback_data: "menu_scan" },
      { text: "📊 Dashboard", callback_data: "menu_dashboard" }
    ],
    [
      { text: "🎯 Targets", callback_data: "view_targets_0" },
      { text: "👥 Contacts", callback_data: "view_contacts_0" },
      { text: "📜 Scan Queue", callback_data: "view_new_domains" }
    ],
    [
      { text: "🛡️ Findings", callback_data: "menu_findings" },
      { text: "🔑 Secrets", callback_data: "menu_secrets_0" },
      { text: "🔌 Services", callback_data: "menu_services_0" }
    ]
  ];

  const lastRow = [{ text: `⚙️ Runner (${runnerStatusText})`, callback_data: "change_runner" }];
  if (isAdmin) {
    lastRow.push({ text: "⚠️ Reset DB", callback_data: "confirm_reset_db" });
  }
  keyboard.push(lastRow);
  if (isAdmin) {
    keyboard.push([{ text: "🛡️ Admin Control Center", callback_data: "admin_home" }]);
  }

  const appUrl = miniAppUrl(env);
  if (appUrl) {
    keyboard.push([{ text: "📱 Open Mini App", web_app: { url: appUrl } }]);
  }

  return { inline_keyboard: keyboard };
};

// Public https origin of this Worker, used to build the Telegram Mini App URL.
// Prefer PUBLIC_URL; fall back to GRAPHQL_ENDPOINT (…/graphql -> origin).
const publicOrigin = (env) => {
  const raw = env?.PUBLIC_URL || env?.GRAPHQL_ENDPOINT || '';
  try { return new URL(raw).origin; } catch (_) { return ''; }
};

// Mini App entry URL. Telegram only accepts https web_app buttons, so callers
// must skip the button when this returns '' (e.g. local http dev).
const miniAppUrl = (env) => {
  const origin = publicOrigin(env);
  return origin.startsWith('https://') ? `${origin}/app` : '';
};

// The slash commands advertised in Telegram's "/" autocomplete and the ☰ menu.
// Kept short and task-focused; the full surface still lives in the dashboard
// and Mini App.
const BOT_COMMANDS = [
  { command: 'start', description: 'Open the cHack control center' },
  { command: 'programs', description: 'Review discovered bug-bounty programs' },
  { command: 'onboard', description: 'Onboard a program from pasted scope' },
  { command: 'discover', description: 'Sweep platforms for new programs' },
  { command: 'monitor', description: 'Schedule continuous monitoring' },
  { command: 'recon', description: 'Full recon scan of a domain' },
  { command: 'web', description: 'Crawl and JS secret mining' },
  { command: 'network', description: 'Port scan a target' },
  { command: 'vulns', description: 'Show vulnerability findings' },
  { command: 'report', description: 'Export a target report' },
  { command: 'dashboard', description: 'Stats and activity overview' },
  { command: 'help', description: 'Show command help' },
];

const BOT_SHORT_DESCRIPTION =
  'Authorized-use recon & bug-bounty automation — discovers programs, proposes scope, scans only what you approve.';

const BOT_DESCRIPTION =
  'cHack C2 — authorized-use offensive-security automation.\n\n' +
  '• Discovers public bug-bounty programs and proposes their scope\n' +
  '• You approve what enters scope; nothing is scanned un-authorized\n' +
  '• Runs recon, web/JS, network and vuln scans on in-scope targets\n' +
  '• Continuous monitoring + findings, driven from here or the Mini App\n\n' +
  'Send /start to begin. Use only on assets you are authorized to test.';

// One-time (per isolate) bot UI setup: advertise the slash commands + profile
// descriptions, and point the ☰ menu button at the Mini App when available.
let botConfigured = false;
const configureBotUI = async (env, bot) => {
  await bot.api.setMyCommands(BOT_COMMANDS);
  try {
    await bot.api.setMyShortDescription({ short_description: BOT_SHORT_DESCRIPTION });
    await bot.api.setMyDescription({ description: BOT_DESCRIPTION });
  } catch (e) { /* description set is best-effort */ }
  const url = miniAppUrl(env);
  await bot.api.setChatMenuButton(
    url
      ? { menu_button: { type: 'web_app', text: 'Open App', web_app: { url } } }
      : { menu_button: { type: 'commands' } }
  );
};

const getBot = (env) => {
  if (botInstance) return botInstance;
  
  const bot = new Bot(env.TELEGRAM_BOT_TOKEN);
  
  // Attach env to bot context
  bot.use((ctx, next) => {
    ctx.env = env;
    return next();
  });

  // Answer all callback queries immediately in background to prevent UI lag/timeout
  bot.use(async (ctx, next) => {
    if (ctx.callbackQuery) {
      await ctx.answerCallbackQuery().catch(() => {});
    }
    await next();
  });
  
  // D1 Grammy Session Middleware
  bot.use(async (ctx, next) => {
    const key = ctx.from?.id ? `session:${ctx.from.id}` : null;
    if (!key) {
      ctx.session = {};
      return next();
    }
    
    try {
      const row = await env.DB.prepare("SELECT value FROM sessions WHERE key = ?").bind(key).first();
      ctx.session = row ? JSON.parse(row.value) : {};
    } catch (err) {
      console.error("D1 session read error:", err.message);
      ctx.session = {};
    }
    
    await next();
    
    try {
      await env.DB.prepare("INSERT OR REPLACE INTO sessions (key, value) VALUES (?, ?)")
        .bind(key, JSON.stringify(ctx.session))
        .run();
    } catch (err) {
      console.error("D1 session write error:", err.message);
    }
  });

  // RBAC access gate middleware.
  // Registers the caller (so admins can later reference/promote them), resolves
  // their effective role, and enforces a minimum of "viewer". Unknown callers
  // are recorded as role='pending' and denied with a friendly message rather
  // than silently dropped. Backward compatible: with no ADMIN_IDS configured the
  // bot stays wide open (every caller resolves to admin via legacyOpen).
  bot.use(async (ctx, next) => {
    if (!ctx.from) return;
    const u = ctx.from;
    const username = u.username ? `@${u.username}` : `user_${u.id}`;

    // Upsert the user row without ever clobbering an assigned role.
    try {
      const existing = await env.DB.prepare(
        "SELECT id FROM users WHERE number_id = ?"
      ).bind(u.id).first();
      if (!existing) {
        await env.DB.prepare(
          `INSERT INTO users (id, username, number_id, first_name, last_name, role)
           VALUES (?, ?, ?, ?, ?, 'pending')`
        ).bind(crypto.randomUUID(), u.username || `user_${u.id}`, u.id,
               u.first_name || '', u.last_name || '').run();
      }
    } catch (err) {
      console.error("user upsert error:", err.message);
    }

    const actor = await resolveActor(env, u);
    ctx.actor = actor;

    // Minimum access is "viewer". A user with no global role but who belongs to
    // at least one team is also admitted (team-scoped access).
    const admitted = actor.hasGlobal('viewer') || actor.memberships.length > 0;
    if (!admitted) {
      console.log(`Access pending/denied for Telegram ID: ${u.id} (${username})`);
      await auditLog(env, {
        actor_user_id: actor.userId, actor_number_id: u.id, actor_label: username,
        source: 'telegram', action: 'access.denied', decision: 'deny',
        target_type: 'user', target: String(u.id),
        detail: { role: actor.role, reason: 'not-provisioned' },
      });
      try {
        await ctx.reply(
          "⛔ <b>Access pending.</b>\n\nYour Telegram account is registered but has " +
          "not been granted a role yet. Ask an administrator to run " +
          `<code>/grant ${u.id} viewer</code> (or a higher role).\n\n` +
          `Your ID: <code>${u.id}</code>`,
          { parse_mode: "HTML" }
        ).catch(() => {});
      } catch (_) { /* ignore */ }
      return;
    }
    await next();
  });

  // Slash commands are reserved for admins. Regular (non-admin) users drive the
  // bot through inline-keyboard buttons instead. Callback queries (button taps)
  // and plain text (e.g. a domain typed into a button flow) always pass through;
  // only an actual /command from a non-admin is intercepted and redirected to
  // the menu. /start and /menu stay open to everyone so they can open the keyboard.
  bot.use(async (ctx, next) => {
    const text = ctx.message?.text || "";
    const isCommand = text.startsWith("/") ||
      (ctx.message?.entities || []).some(e => e.type === "bot_command" && e.offset === 0);
    if (!isCommand) { await next(); return; }

    const actor = ctx.actor || await resolveActor(env, ctx.from);
    if (actor.hasGlobal("admin")) { await next(); return; } // admins: full command access

    const cmd = text.replace(/^\//, "").split(/[@\s]/)[0].toLowerCase();
    if (cmd === "start" || cmd === "menu") { await next(); return; }

    const menuMarkup = await createMainMenu(ctx, env);
    await ctx.reply(
      "🔘 <b>Button mode.</b>\n\nSlash commands are reserved for administrators. " +
      "Use the buttons below to navigate — everything you can do is one tap away.",
      { parse_mode: "HTML", reply_markup: menuMarkup }
    ).catch(() => {});
    // Do not call next(): the command handler is skipped for non-admins.
  });

  // Helper: auto-register user on first bot interaction
  const registerUser = async (ctx) => {
    if (ctx.session?.user_registered) return;
    
    const user = ctx.from;
    if (user) {
      const username = user.username || `user_${user.id}`;
      try {
        const existing = await env.DB.prepare("SELECT id FROM users WHERE number_id = ?").bind(user.id).first();
        if (!existing) {
          const uuid = crypto.randomUUID();
          await env.DB.prepare(
            `INSERT INTO users (id, username, number_id, first_name, last_name)
             VALUES (?, ?, ?, ?, ?)`
          ).bind(uuid, username, user.id, user.first_name || '', user.last_name || '').run();
        }
        if (!ctx.session) ctx.session = {};
        ctx.session.user_registered = true;
      } catch (err) {
        console.error("D1 user registration error:", err.message);
        if (!ctx.session) ctx.session = {};
        ctx.session.user_registered = true;
      }
    }
  };

  // Helper: format domain row
  const formatDomainLine = (d) => {
    const host = d.host || 'N/A';
    const domData = parseJson(d.data);
    const status_code = domData.status_code;
    const title = domData.title || 'No Title';
    const tech = (domData.tech || []).join(', ') || 'No Tech';

    let statusStr = "⚪ ???";
    if (status_code !== undefined && status_code !== null) {
      const code = Number(status_code);
      if (code >= 200 && code < 300) statusStr = `🟢 ${code}`;
      else if (code >= 300 && code < 400) statusStr = `🔵 ${code}`;
      else if (code >= 400 && code < 500) statusStr = `🔴 ${code}`;
      else if (code >= 500 && code < 600) statusStr = `🟣 ${code}`;
      else statusStr = `⚪ ${code}`;
    }
    return `<b><a href="http://${host}">${escapeHtml(host)}</a></b> ${statusStr} ~ <i>${escapeHtml(title)}</i> | <code>${escapeHtml(tech)}</code>`;
  };

  // Map scan type -> audit action name.
  const SCAN_ACTION = {
    domain: 'scan.recon', person: 'scan.person', company: 'scan.company',
    infogather: 'scan.infogather', web: 'scan.web', network: 'scan.network',
  };

  // Queue scan helper. Enforces per-user/team target scope before enqueuing,
  // records attribution on the job row, writes an audit entry (allow/deny), and
  // honours orchestration opts (priority, region). Returns the job id on
  // success, or null if the scan was denied (a reply has already been sent).
  const triggerScan = async (ctx, type, value, runner = 'default', opts = {}) => {
    const priority = Number.isFinite(opts.priority) ? opts.priority : 0;
    const region = opts.region || null;
    const actor = ctx.actor || await resolveActor(env, ctx.from);
    const userId = ctx.from?.id || 0;
    const action = SCAN_ACTION[type] || 'scan.unknown';

    // Scope enforcement.
    const scope = await checkScanScope(env, actor, value);
    if (!scope.allowed) {
      await auditLog(env, {
        actor_user_id: actor.userId, actor_number_id: userId, actor_label: actor.username,
        source: 'telegram', action, decision: 'deny',
        target_type: type, target: value, company_id: scope.companyId,
        detail: { reason: scope.reason, role: actor.role },
      });
      const msg = scope.reason === 'insufficient-role'
        ? "⛔ <b>Not allowed.</b> Scanning requires the <code>operator</code> role or higher. " +
          "Ask an admin to raise your role with <code>/role</code>."
        : "⛔ <b>Out of scope.</b> That target belongs to a team you are not a member of. " +
          "Ask an admin to add you with <code>/grant</code>, or pick an in-scope target.";
      await ctx.reply(msg, { parse_mode: "HTML" }).catch(() => {});
      return null;
    }

    let command = "";
    if (type === 'domain') {
      command = `-d ${value} --sender-id ${userId}`;
    } else if (type === 'person') {
      command = `-p "${value}" --sender-id ${userId}`;
    } else if (type === 'company') {
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value);
      if (isDomain) {
        command = `-d ${value} --sender-id ${userId}`;
      } else {
        command = `-c "${value}" --sender-id ${userId}`;
      }
    } else if (type === 'infogather') {
      command = `--info-gather ${value} --sender-id ${userId}`;
    } else if (type === 'web') {
      command = `--web ${value} --sender-id ${userId}`;
    } else if (type === 'network') {
      command = `--network ${value} --sender-id ${userId}`;
    }

    // Person targets are individuals, not hosts: tag the job so the runner
    // routes it past host-scope_guard and authorizes it by company instead.
    const jobType = type === 'person' ? 'person_osint' : null;

    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO scan_jobs
         (id, command, domain, runner, region, priority, status, job_type, requested_by, requested_by_number_id, company_id, source)
       VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, 'telegram')`
    ).bind(id, command, value, runner, region, priority, jobType, actor.userId, userId, scope.companyId).run();

    await auditLog(env, {
      actor_user_id: actor.userId, actor_number_id: userId, actor_label: actor.username,
      source: 'telegram', action, decision: 'allow',
      target_type: type, target: value, company_id: scope.companyId,
      detail: { job_id: id, runner, scope: scope.reason },
    });
    return id;
  };

  // Guard a handler to a minimum global role. On failure it audits the denial,
  // replies, and returns false so the caller can `return` early.
  const requireRole = async (ctx, min, action, targetType = null, target = null) => {
    const actor = ctx.actor || await resolveActor(env, ctx.from);
    if (actor.hasGlobal(min)) return true;
    await auditLog(env, {
      actor_user_id: actor.userId, actor_number_id: ctx.from?.id || 0, actor_label: actor.username,
      source: 'telegram', action, decision: 'deny', target_type: targetType, target,
      detail: { reason: 'insufficient-role', required: min, role: actor.role },
    });
    const msg = `⛔ Requires the ${min} role. Ask an admin to raise your role.`;
    if (ctx.callbackQuery) {
      await ctx.answerCallbackQuery({ text: msg, show_alert: true }).catch(() => {});
    } else {
      await ctx.reply(msg, { parse_mode: "HTML" }).catch(() => {});
    }
    return false;
  };

  const createRunnerKeyboard = async () => {
    const keyboard = [];
    try {
      const cutoff = Math.floor(Date.now() / 1000) - 60;
      const { results } = await env.DB.prepare(
        "SELECT name, ip, country, last_seen FROM runners ORDER BY name ASC"
      ).all();

      if (results.length > 0) {
        results.forEach(r => {
          const isActive = r.last_seen >= cutoff;
          const statusIndicator = isActive ? "🟢" : "🔴";
          const flag = getFlagEmoji(r.country);
          keyboard.push([{
            text: `${statusIndicator} ${flag} ${r.name} (${r.ip || 'no IP'})`,
            callback_data: `manage_runner:${r.name}`
          }]);
        });
      }
    } catch (err) {
      console.error("D1 error in createRunnerKeyboard:", err.message);
    }
    
    keyboard.push([
      { text: "🔄 Refresh", callback_data: "change_runner" },
      { text: "🔙 Main Menu", callback_data: "main_menu" }
    ]);
    return { inline_keyboard: keyboard };
  };

  const safeEditMessageText = async (ctx, text, options) => {
    try {
      return await ctx.editMessageText(text, options);
    } catch (err) {
      const desc = err && (err.description || (err.error && err.error.description) || err.message || "");
      if (desc && String(desc).toLowerCase().includes("message is not modified")) {
        // Ignored
      } else {
        throw err;
      }
    }
  };

  // ----------------------------------------------------
  // Bot Slash Commands
  // ----------------------------------------------------
  bot.command(["start", "menu"], async (ctx) => {
    await registerUser(ctx);
    if (!ctx.session.selected_runner) {
      ctx.session.selected_runner = 'default';
    }
    ctx.session.step = 'MAIN_MENU';
    const menuMarkup = await createMainMenu(ctx, env);
    await ctx.reply(
      "🛰️ <b>cHack C2 Control Center</b>\n\n" +
      "Authorized-use recon &amp; bug-bounty automation. Use the menu below, or:\n\n" +
      "🪪 <b>Onboard &amp; discover</b>\n" +
      "• <code>/programs</code> — review discovered programs &amp; approve scope\n" +
      "• <code>/discover</code> — sweep platforms for new programs now\n" +
      "• <code>/onboard</code> — add a program from pasted scope\n\n" +
      "🎯 <b>Scan &amp; monitor</b> (in-scope targets only)\n" +
      "• <code>/recon</code> · <code>/web</code> · <code>/network</code> · <code>/vulns</code> · <code>/report</code>\n" +
      "• <code>/monitor</code> — schedule continuous monitoring\n\n" +
      "Every new program's scope is <b>approved by you</b> before anything is scanned. " +
      "<code>/help</code> for the full list.",
      {
        parse_mode: "HTML",
        reply_markup: menuMarkup
      }
    );
  });

  bot.command(["app", "webapp"], async (ctx) => {
    await registerUser(ctx);
    const appUrl = miniAppUrl(env);
    if (!appUrl) {
      await ctx.reply(
        "📱 <b>Mini App not configured.</b>\n\nSet <code>PUBLIC_URL</code> (or " +
        "<code>GRAPHQL_ENDPOINT</code>) to this Worker's public https URL and redeploy.",
        { parse_mode: "HTML" }
      );
      return;
    }
    await ctx.reply("📱 <b>cHack Mini App</b>\n\nTap below to open the live dashboard inside Telegram:", {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: "📱 Open Mini App", web_app: { url: appUrl } }]] },
    });
  });

  // Replace the chat input's default "commands" (☰) menu button with one that
  // launches the Mini App. This is a global bot setting (admin-only).
  bot.command("setmenu", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'bot.setmenu')) return;
    const appUrl = miniAppUrl(env);
    if (!appUrl) {
      await ctx.reply(
        "❌ Set <code>PUBLIC_URL</code> to this Worker's https URL first, then run /setmenu.",
        { parse_mode: "HTML" }
      );
      return;
    }
    try {
      await configureBotUI(env, getBot(env));
      await ctx.reply("✅ Commands cleared and the menu button now opens the Mini App. (Reopen the chat to see it.)");
    } catch (err) {
      await ctx.reply(`❌ Failed to update bot UI: ${escapeHtml(err.message)}`);
    }
  });

  // Restore the default commands (☰) menu button.
  bot.command("resetmenu", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'bot.resetmenu')) return;
    try {
      await ctx.api.setChatMenuButton({ menu_button: { type: "commands" } });
      await ctx.reply("✅ Menu button reset to the default commands list.");
    } catch (err) {
      await ctx.reply(`❌ Failed to reset menu button: ${escapeHtml(err.message)}`);
    }
  });

  bot.command(["dashboard", "stats"], async (ctx) => {
    await registerUser(ctx);
    try {
      const compCount = (await env.DB.prepare("SELECT count(*) as cnt FROM companies").first())?.cnt || 0;
      const domCount = (await env.DB.prepare("SELECT count(*) as cnt FROM domains").first())?.cnt || 0;
      const peopleCount = (await env.DB.prepare("SELECT count(*) as cnt FROM people").first())?.cnt || 0;
      
      const { results: findings } = await env.DB.prepare("SELECT severity, status FROM findings").all();
      const crit = findings.filter(f => f.severity?.toLowerCase() === 'critical').length;
      const high = findings.filter(f => f.severity?.toLowerCase() === 'high').length;
      const med = findings.filter(f => f.severity?.toLowerCase() === 'medium').length;
      const low = findings.filter(f => f.severity?.toLowerCase() === 'low').length;
      const info = findings.filter(f => f.severity?.toLowerCase() === 'info').length;
      const resolved = findings.filter(f => f.status === 'resolved').length;

      const secretsCount = (await env.DB.prepare("SELECT count(*) as cnt FROM secrets").first())?.cnt || 0;
      const servicesCount = (await env.DB.prepare("SELECT count(*) as cnt FROM network_services").first())?.cnt || 0;
      const runningJobs = (await env.DB.prepare("SELECT count(*) as cnt FROM scan_jobs WHERE status IN ('pending', 'running')").first())?.cnt || 0;
      
      const cutoff = Math.floor(Date.now() / 1000) - 60;
      const onlineRunners = (await env.DB.prepare("SELECT count(*) as cnt FROM runners WHERE last_seen >= ?").bind(cutoff).first())?.cnt || 0;
      const totalRunners = (await env.DB.prepare("SELECT count(*) as cnt FROM runners").first())?.cnt || 0;

      const text =
        `📊 <b>cHack Intelligence & Management Dashboard</b>\n\n` +
        `🎯 <b>Targets & Assets:</b>\n` +
        `• 🏢 Companies / Scopes: <b>${compCount}</b>\n` +
        `• 🌐 Domains / Subdomains: <b>${domCount}</b>\n` +
        `• 👥 Contacts & People: <b>${peopleCount}</b>\n\n` +
        `🛡️ <b>Findings & Vulnerabilities (${findings.length}):</b>\n` +
        `• 🔴 Critical: <b>${crit}</b>\n` +
        `• 🟠 High: <b>${high}</b>\n` +
        `• 🟡 Medium: <b>${med}</b>\n` +
        `• 🔵 Low: <b>${low}</b>\n` +
        `• ⚪ Info: <b>${info}</b>\n` +
        `• ✅ Resolved / Fixed: <b>${resolved}</b>\n\n` +
        `🔑 <b>Secrets & Leaks:</b> <b>${secretsCount}</b>\n` +
        `🔌 <b>Network Services & Open Ports:</b> <b>${servicesCount}</b>\n\n` +
        `⚙️ <b>System & Infrastructure:</b>\n` +
        `• ⏳ Active / Queued Jobs: <b>${runningJobs}</b>\n` +
        `• 🖥️ Runners Online: <b>${onlineRunners} / ${totalRunners}</b>`;

      await ctx.reply(text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🔄 Refresh", callback_data: "menu_dashboard" },
              { text: "🧹 Clear Finished Jobs", callback_data: "action_clean_queue" }
            ],
            [
              { text: "🎯 Manage Targets", callback_data: "view_targets_0" },
              { text: "🛡️ Triage Findings", callback_data: "menu_findings" }
            ],
            [
              { text: "⚠️ Reset Database", callback_data: "confirm_reset_db" },
              { text: "🔙 Main Menu", callback_data: "main_menu" }
            ]
          ]
        }
      });
    } catch (err) {
      await ctx.reply(`❌ Error loading dashboard: ${escapeHtml(err.message)}`);
    }
  });

  bot.command(["targets", "companies"], async (ctx) => {
    await registerUser(ctx);
    ctx.session.step = 'MAIN_MENU';
    const { results: companies } = await env.DB.prepare("SELECT * FROM companies ORDER BY created_at DESC LIMIT 8 OFFSET 0").all();
    const count = (await env.DB.prepare("SELECT count(*) as cnt FROM companies").first())?.cnt || 0;
    const totalPages = Math.ceil(count / 8) || 1;

    const keyboard = [];
    for (const c of companies) {
      const dCount = (await env.DB.prepare("SELECT count(*) as cnt FROM domains WHERE company_id = ?").bind(c.id).first())?.cnt || 0;
      keyboard.push([{ text: `🏢 ${c.name} (${dCount} domains)`, callback_data: `view_company_${c.id}` }]);
    }
    keyboard.push([{ text: "➕ Add Target Company", callback_data: "target_company" }]);
    if (totalPages > 1) {
      keyboard.push([{ text: "Next ➡️", callback_data: "view_targets_1" }]);
    }
    keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

    await ctx.reply(`🎯 <b>Targets / Companies</b> (Page 1/${totalPages})\n\nSelect a company to view details, domains, or launch scans:`, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: keyboard }
    });
  });

  bot.command(["contacts", "people"], async (ctx) => {
    await registerUser(ctx);
    ctx.session.step = 'MAIN_MENU';
    const { results: people } = await env.DB.prepare("SELECT * FROM people ORDER BY created_at DESC LIMIT 8 OFFSET 0").all();
    const count = (await env.DB.prepare("SELECT count(*) as cnt FROM people").first())?.cnt || 0;
    const totalPages = Math.ceil(count / 8) || 1;

    const keyboard = [];
    for (const p of people) {
      const name = `${p.given_name || ''} ${p.family_name || ''}`.trim() || 'Unnamed';
      const badge = osintBadge(p.data);
      keyboard.push([{ text: `👤 ${name}${badge ? ` ${badge}` : ''}`, callback_data: `view_contact_${p.id}` }]);
    }
    keyboard.push([{ text: "➕ Add New Person", callback_data: "target_person" }]);
    if (totalPages > 1) {
      keyboard.push([{ text: "Next ➡️", callback_data: "view_contacts_1" }]);
    }
    keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

    await ctx.reply(`👥 <b>Contacts & People</b> (Page 1/${totalPages})\n\nSelect a person to inspect details, launch OSINT search, or remove:`, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: keyboard }
    });
  });

  bot.command(["queue", "jobs"], async (ctx) => {
    await registerUser(ctx);
    ctx.session.step = 'MAIN_MENU';
    const { results: jobs } = await env.DB.prepare(
      "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT 10"
    ).all();

    if (!jobs.length) {
      return await ctx.reply("📜 <b>Scan Queue</b>\n\nNo scan jobs found in the database.", {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "🚀 Launch Scan", callback_data: "menu_scan" }],
            [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
          ]
        }
      });
    }

    const keyboard = [];
    jobs.forEach(job => {
      let badge = "⏳";
      if (job.status === 'running') badge = "🔄";
      else if (job.status === 'completed') badge = "✅";
      else if (job.status === 'failed') badge = "🛑";
      keyboard.push([{ text: `${badge} ${job.domain} (${job.runner || 'default'})`, callback_data: `manage_job:${job.id}` }]);
    });

    keyboard.push([
      { text: "🔄 Refresh", callback_data: "view_new_domains" },
      { text: "🧹 Clean Finished", callback_data: "action_clean_queue" }
    ]);
    keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

    await ctx.reply(`📜 <b>Scan Jobs Queue (${jobs.length})</b>\n\nClick any job to view live logs, stop, or restart:`, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: keyboard }
    });
  });

  bot.command("clean", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'queue.clean')) return;
    const res = await env.DB.prepare("DELETE FROM scan_jobs WHERE status IN ('completed', 'failed')").run();
    await auditLog(env, {
      actor_user_id: ctx.actor?.userId, actor_number_id: ctx.from?.id || 0,
      actor_label: ctx.actor?.username, source: 'telegram', action: 'queue.clean',
      target_type: 'job', detail: {},
    });
    await ctx.reply(`🧹 Cleaned up finished/failed scan jobs from queue.`);
  });

  bot.command("newcompany", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'company.create')) return;
    ctx.session.step = 'COMPANY_INPUT';
    await ctx.reply("🏢 <b>Target: Company / Domain</b>\n\nPlease send me the company name or domain (e.g. <code>CHTH Corp</code> or <code>chth.xyz</code>):", {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]]
      }
    });
  });

  bot.command("newperson", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'person.create')) return;
    ctx.session.step = 'PERSON_INPUT';
    await ctx.reply("🔍 <b>Target: Person</b>\n\nSend me the person's phone number (<code>+1555...</code>), username (<code>@che...</code>), or name (e.g. <code>Cheth Ober</code>):", {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]]
      }
    });
  });

  bot.command("delcompany", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'company.delete')) return;
    const name = ctx.match?.trim();
    if (!name) {
      return await ctx.reply("❌ Usage: <code>/delcompany &lt;company name or slug&gt;</code>", { parse_mode: "HTML" });
    }
    const comp = await env.DB.prepare("SELECT * FROM companies WHERE lower(name) = lower(?) OR lower(slug) = lower(?)").bind(name, name).first();
    if (!comp) {
      return await ctx.reply(`❌ Company <code>${escapeHtml(name)}</code> not found.`, { parse_mode: "HTML" });
    }
    await env.DB.prepare("DELETE FROM companies WHERE id = ?").bind(comp.id).run();
    await auditLog(env, {
      actor_user_id: ctx.actor?.userId, actor_number_id: ctx.from?.id || 0, actor_label: ctx.actor?.username,
      source: 'telegram', action: 'company.delete', target_type: 'company', target: comp.name, company_id: comp.id, detail: {},
    });
    await ctx.reply(`🗑️ Company <code>${escapeHtml(comp.name)}</code> and all associated domains/findings deleted.`, { parse_mode: "HTML" });
  });

  bot.command("deldomain", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'domain.delete')) return;
    const host = ctx.match?.trim()?.toLowerCase();
    if (!host) {
      return await ctx.reply("❌ Usage: <code>/deldomain &lt;host&gt;</code>", { parse_mode: "HTML" });
    }
    const dom = await env.DB.prepare("SELECT * FROM domains WHERE lower(host) = lower(?)").bind(host).first();
    if (!dom) {
      return await ctx.reply(`❌ Domain <code>${escapeHtml(host)}</code> not found.`, { parse_mode: "HTML" });
    }
    await env.DB.prepare("DELETE FROM domains WHERE id = ?").bind(dom.id).run();
    await auditLog(env, {
      actor_user_id: ctx.actor?.userId, actor_number_id: ctx.from?.id || 0, actor_label: ctx.actor?.username,
      source: 'telegram', action: 'domain.delete', target_type: 'domain', target: host, company_id: dom.company_id, detail: {},
    });
    await ctx.reply(`🗑️ Domain <code>${escapeHtml(host)}</code> deleted.`, { parse_mode: "HTML" });
  });

  bot.command("delperson", async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'admin', 'person.delete')) return;
    const name = ctx.match?.trim();
    if (!name) {
      return await ctx.reply("❌ Usage: <code>/delperson &lt;first name&gt;</code>", { parse_mode: "HTML" });
    }
    const person = await env.DB.prepare("SELECT * FROM people WHERE lower(given_name) = lower(?) OR lower(given_name || ' ' || coalesce(family_name, '')) = lower(?)").bind(name, name).first();
    if (!person) {
      return await ctx.reply(`❌ Person <code>${escapeHtml(name)}</code> not found.`, { parse_mode: "HTML" });
    }
    await env.DB.prepare("DELETE FROM people WHERE id = ?").bind(person.id).run();
    await auditLog(env, {
      actor_user_id: ctx.actor?.userId, actor_number_id: ctx.from?.id || 0, actor_label: ctx.actor?.username,
      source: 'telegram', action: 'person.delete', target_type: 'person', target: name, company_id: person.company_id, detail: {},
    });
    await ctx.reply(`🗑️ Contact <code>${escapeHtml(person.given_name)} ${escapeHtml(person.family_name || '')}</code> deleted.`, { parse_mode: "HTML" });
  });

  bot.command("getuser", async (ctx) => {
    const username = ctx.match?.trim();
    if (!username) {
      return await ctx.reply("❌ Usage: <code>/getuser &lt;username&gt;</code>", { parse_mode: "HTML" });
    }
    const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
    if (!user) {
      return await ctx.reply(`❌ User <code>${escapeHtml(username)}</code> not found.`, { parse_mode: "HTML" });
    }
    await ctx.reply(
      `👤 <b>User: ${escapeHtml(user.username)}</b>\n\n` +
      `• <b>ID:</b> <code>${user.id}</code>\n` +
      `• <b>Telegram ID:</b> <code>${user.number_id || 'N/A'}</code>\n` +
      `• <b>First Name:</b> ${escapeHtml(user.first_name || 'N/A')}\n` +
      `• <b>Last Name:</b> ${escapeHtml(user.last_name || 'N/A')}\n` +
      `• <b>Created At:</b> <code>${user.created_at}</code>`,
      { parse_mode: "HTML" }
    );
  });

  bot.command("getcompany", async (ctx) => {
    const company_name = ctx.match?.trim();
    if (!company_name) {
      return await ctx.reply("❌ Usage: <code>/getcompany &lt;company name&gt;</code>", { parse_mode: "HTML" });
    }
    const company = await env.DB.prepare("SELECT * FROM companies WHERE lower(name) = lower(?) OR lower(slug) = lower(?)").bind(company_name, company_name).first();
    if (!company) {
      return await ctx.reply(`❌ Company <code>${escapeHtml(company_name)}</code> not found.`, { parse_mode: "HTML" });
    }
    const { results: domains } = await env.DB.prepare("SELECT host FROM domains WHERE company_id = ?").bind(company.id).all();
    const { results: people } = await env.DB.prepare("SELECT given_name, family_name FROM people WHERE company_id = ?").bind(company.id).all();
    
    const comp_data = parseJson(company.data);
    const phase = comp_data.phase || 'N/A';
    const domains_list = domains.length ? domains.map(d => `• <code>${escapeHtml(d.host)}</code>`).join('\n') : "None";
    const people_list = people.length ? people.map(p => `• ${escapeHtml(p.given_name)} ${escapeHtml(p.family_name || '')}`).join('\n') : "None";

    await ctx.reply(
      `🏢 <b>Company: ${escapeHtml(company.name)}</b>\n\n` +
      `• <b>ID:</b> <code>${company.id}</code>\n` +
      `• <b>Slug:</b> <code>${company.slug || 'N/A'}</code>\n` +
      `• <b>Description:</b> ${escapeHtml(company.description || 'N/A')}\n` +
      `• <b>Phase:</b> <code>${phase}</code>\n` +
      `• <b>Created At:</b> <code>${company.created_at}</code>\n\n` +
      `🌐 <b>Domains (${domains.length}):</b>\n${domains_list}\n\n` +
      `👤 <b>People (${people.length}):</b>\n${people_list}`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "🌐 View Domains", callback_data: `view_company_domains_${company.id}_0` }],
            [{ text: "🚀 Launch Recon", callback_data: `scan_company_action_${company.id}` }]
          ]
        }
      }
    );
  });

  bot.command("getdomain", async (ctx) => {
    const host = ctx.match?.trim()?.toLowerCase();
    if (!host) {
      return await ctx.reply("❌ Usage: <code>/getdomain &lt;host&gt;</code>", { parse_mode: "HTML" });
    }
    const domain = await env.DB.prepare("SELECT * FROM domains WHERE lower(host) = lower(?)").bind(host).first();
    if (!domain) {
      return await ctx.reply(`❌ Domain <code>${escapeHtml(host)}</code> not found.`, { parse_mode: "HTML" });
    }
    const company = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(domain.company_id).first();
    const domData = parseJson(domain.data);
    const title = domData.title || 'N/A';
    const webserver = domData.webserver || 'N/A';
    const status_code = domData.status_code || 'N/A';
    const tech = (domData.tech || []).join(', ') || 'N/A';

    await ctx.reply(
      `🌐 <b>Domain: ${escapeHtml(domain.host)}</b>\n\n` +
      `• <b>ID:</b> <code>${domain.id}</code>\n` +
      `• <b>Company:</b> ${company ? escapeHtml(company.name) : 'N/A'}\n` +
      `• <b>Canonical URL:</b> ${escapeHtml(domain.canonical_url || 'N/A')}\n` +
      `• <b>Status Code:</b> <code>${status_code}</code>\n` +
      `• <b>Title:</b> ${escapeHtml(title)}\n` +
      `• <b>Web Server:</b> ${escapeHtml(webserver)}\n` +
      `• <b>Tech:</b> ${escapeHtml(tech)}\n` +
      `• <b>Created At:</b> <code>${domain.created_at}</code>`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🚀 Recon", callback_data: `scan_dom_recon_${domain.id}` },
              { text: "🛡️ Findings", callback_data: `view_dom_vulns_${domain.id}_0` }
            ]
          ]
        }
      }
    );
  });

  bot.command(["getpeople", "getperson"], async (ctx) => {
    const args = ctx.match?.trim()?.split(/\s+/) || [];
    if (args.length === 0 || args[0] === '') {
      return await ctx.reply("❌ Usage: <code>/getpeople &lt;first name&gt; [last name]</code>", { parse_mode: "HTML" });
    }
    const givenName = args[0];
    const familyName = args[1] || null;

    let query = "SELECT * FROM people WHERE lower(given_name) = lower(?)";
    const binds = [givenName];
    if (familyName) {
      query += " AND lower(family_name) = lower(?)";
      binds.push(familyName);
    }
    
    const { results: people } = await env.DB.prepare(query).bind(...binds).all();
    if (!people.length) {
      const name_str = familyName ? `${givenName} ${familyName}` : givenName;
      return await ctx.reply(`❌ Person <code>${escapeHtml(name_str)}</code> not found.`, { parse_mode: "HTML" });
    }

    const msgs = [];
    for (const p of people.slice(0, 5)) {
      const emails = parseJson(p.emails).join(', ') || "None";
      const phones = parseJson(p.phones).join(', ') || "None";
      const comp = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(p.company_id).first();
      
      msgs.push(
        `👤 <b>Person: ${escapeHtml(p.given_name)} ${escapeHtml(p.family_name || '')}</b>\n` +
        `• <b>ID:</b> <code>${p.id}</code>\n` +
        `• <b>Company:</b> ${comp ? escapeHtml(comp.name) : 'N/A'}\n` +
        `• <b>Emails:</b> ${escapeHtml(emails)}\n` +
        `• <b>Phones:</b> ${escapeHtml(phones)}\n` +
        `• <b>Notes:</b> ${escapeHtml(p.notes || 'None')}` +
        formatOsintSummary(p.data)
      );
    }
    await ctx.reply(msgs.join('\n\n---\n\n'), { parse_mode: "HTML" });
  });

  bot.command("getstatus", async (ctx) => {
    const statusStr = ctx.match?.trim();
    if (!statusStr || isNaN(Number(statusStr))) {
      return await ctx.reply("❌ Usage: <code>/getstatus &lt;status_code&gt;</code>", { parse_mode: "HTML" });
    }
    const statusCode = Number(statusStr);
    
    const { results: domains } = await env.DB.prepare(
      "SELECT * FROM domains WHERE CAST(json_extract(data, '$.status_code') AS INTEGER) = ? LIMIT 20"
    ).bind(statusCode).all();

    if (!domains.length) {
      return await ctx.reply(`❌ No domains found with status code <code>${statusCode}</code>.`, { parse_mode: "HTML" });
    }

    const lines = domains.map(d => {
      const domData = parseJson(d.data);
      const title = domData.title || "No Title";
      return `• <code>${escapeHtml(d.host)}</code> - <i>${escapeHtml(title)}</i>`;
    });

    await ctx.reply(
      `🔍 <b>Domains with Status Code ${statusCode}:</b>\n` +
      lines.join('\n'),
      { parse_mode: "HTML" }
    );
  });

  bot.command("recon", async (ctx) => {
    await registerUser(ctx);
    const domain = ctx.match?.trim();
    if (!domain) {
      return await ctx.reply("❌ Usage: <code>/recon &lt;domain&gt;</code>", { parse_mode: "HTML" });
    }
    const runner = ctx.session?.selected_runner || 'default';
    const jobId = await triggerScan(ctx, 'domain', domain, runner);
    if (!jobId) return; // scan denied by scope/role (reply already sent)
    await ctx.reply(
      `🚀 <b>Full Recon Scan Queued</b>\n\n` +
      `• <b>Target:</b> <code>${escapeHtml(domain)}</code>\n` +
      `• <b>Runner:</b> <code>${runner}</code>\n` +
      `• <b>Job ID:</b> <code>${jobId}</code>`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "📜 Inspect Live Job", callback_data: `manage_job:${jobId}` }],
            [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
          ]
        }
      }
    );
  });

  bot.command("infogather", async (ctx) => {
    await registerUser(ctx);
    const domain = ctx.match?.trim();
    if (!domain) {
      return await ctx.reply("❌ Usage: <code>/infogather &lt;domain&gt;</code>", { parse_mode: "HTML" });
    }
    const runner = ctx.session?.selected_runner || 'default';
    const jobId = await triggerScan(ctx, 'infogather', domain, runner);
    if (!jobId) return; // scan denied by scope/role (reply already sent)
    await ctx.reply(
      `🔍 <b>Info-Gathering Scan Queued</b>\n\n` +
      `• <b>Target:</b> <code>${escapeHtml(domain)}</code>\n` +
      `• <b>Runner:</b> <code>${runner}</code>\n` +
      `• <b>Job ID:</b> <code>${jobId}</code>`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "📜 Inspect Live Job", callback_data: `manage_job:${jobId}` }],
            [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
          ]
        }
      }
    );
  });

  bot.command("web", async (ctx) => {
    await registerUser(ctx);
    const domain = ctx.match?.trim();
    if (!domain) {
      return await ctx.reply("❌ Usage: <code>/web &lt;domain&gt;</code>", { parse_mode: "HTML" });
    }
    const runner = ctx.session?.selected_runner || 'default';
    const jobId = await triggerScan(ctx, 'web', domain, runner);
    if (!jobId) return; // scan denied by scope/role (reply already sent)
    await ctx.reply(
      `🌐 <b>Web Recon & Crawl Queued</b>\n\n` +
      `• <b>Target:</b> <code>${escapeHtml(domain)}</code>\n` +
      `• <b>Runner:</b> <code>${runner}</code>\n` +
      `• <b>Job ID:</b> <code>${jobId}</code>`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "📜 Inspect Live Job", callback_data: `manage_job:${jobId}` }],
            [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
          ]
        }
      }
    );
  });

  bot.command("network", async (ctx) => {
    await registerUser(ctx);
    const target = ctx.match?.trim();
    if (!target) {
      return await ctx.reply("❌ Usage: <code>/network &lt;target/ip/cidr&gt;</code>", { parse_mode: "HTML" });
    }
    const runner = ctx.session?.selected_runner || 'default';
    const jobId = await triggerScan(ctx, 'network', target, runner);
    if (!jobId) return; // scan denied by scope/role (reply already sent)
    await ctx.reply(
      `🔌 <b>Network & Port Scan Queued</b>\n\n` +
      `• <b>Target:</b> <code>${escapeHtml(target)}</code>\n` +
      `• <b>Runner:</b> <code>${runner}</code>\n` +
      `• <b>Job ID:</b> <code>${jobId}</code>`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "📜 Inspect Live Job", callback_data: `manage_job:${jobId}` }],
            [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
          ]
        }
      }
    );
  });

  // ----------------------------------------------------
  // Autonomous onboarding (Phase 1) — human-gated program intake
  // ----------------------------------------------------
  // /onboard <platform> <handle>  then paste the program's scope text on the
  // following lines (or reply to a message that contains it). The scope is
  // stored in D1 and a runner parses it; the operator approves the proposed
  // hosts before anything is written to scope.txt. Nothing is scanned here.
  bot.command("onboard", async (ctx) => {
    await registerUser(ctx);
    if (!(await requireRole(ctx, 'operator', 'program.onboard', 'program'))) return;

    const raw = (ctx.match || "").trim();
    const replied = ctx.message?.reply_to_message?.text || ctx.message?.reply_to_message?.caption || "";
    const nl = raw.indexOf("\n");
    const header = (nl === -1 ? raw : raw.slice(0, nl)).trim();
    let scopeText = (nl === -1 ? "" : raw.slice(nl + 1)).trim();
    if (!scopeText && replied) scopeText = replied.trim();

    const parts = header.split(/\s+/).filter(Boolean);
    const valid = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "manual"];
    const platform = valid.includes((parts[0] || "").toLowerCase()) ? parts[0].toLowerCase() : "manual";
    const handle = (platform === "manual" ? parts[0] : parts[1]) || null;

    if (!scopeText) {
      return await ctx.reply(
        "🪪 <b>Onboard a bug-bounty program</b>\n\n" +
        "<code>/onboard &lt;platform&gt; &lt;handle&gt;</code>\n" +
        "then paste the program's scope text on the next lines, " +
        "or reply to a message containing it.\n\n" +
        "Platforms: <code>hackerone</code> · <code>bugcrowd</code> · <code>intigriti</code> · <code>yeswehack</code> · <code>manual</code>\n\n" +
        "Nothing is scanned until you approve the parsed scope.",
        { parse_mode: "HTML" }
      );
    }

    const pid = crypto.randomUUID();
    try {
      await env.DB.prepare(
        "INSERT INTO bb_programs (id, platform, handle, name, scope_raw, status, created_by) VALUES (?, ?, ?, ?, ?, 'new', ?)"
      ).bind(pid, platform, handle, handle || platform, scopeText, ctx.from.id).run();
    } catch (e) {
      return await ctx.reply("❌ Could not store program: " + escapeHtml(e.message), { parse_mode: "HTML" });
    }

    // Queue a parse job referenced only by id (no scope text in the command
    // string, which the daemon eval-guards). domain='' so the daemon skips host
    // scope_guard (job_type 'onboard' is read-only).
    const runner = ctx.session?.selected_runner || 'default';
    const jobId = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO scan_jobs (id, command, domain, runner, status, job_type, requested_by_number_id, source) VALUES (?, ?, '', ?, 'pending', 'onboard', ?, 'telegram')"
    ).bind(jobId, `--onboard-process ${pid} --sender-id ${ctx.from.id}`, runner, ctx.from.id).run();

    await auditLog(env, {
      actor_number_id: ctx.from.id, actor_label: ctx.from.username,
      source: 'telegram', action: 'program.onboard', decision: 'allow',
      target_type: 'program', target: handle || platform,
      detail: { program_id: pid, job_id: jobId, platform },
    });

    await ctx.reply(
      `🔎 <b>Parsing scope for</b> <code>${escapeHtml(handle || platform)}</code> [${platform}]…\n\n` +
      `• Runner: <code>${runner}</code>\n` +
      `• Job: <code>${jobId}</code>\n\n` +
      `I'll send the proposed scope for your approval once it's parsed.`,
      { parse_mode: "HTML" }
    );
  });

  // Review discovered / pending programs and kick off parsing+approval.
  bot.command(["programs", "discovered"], async (ctx) => {
    await registerUser(ctx);
    if (!(await requireRole(ctx, 'operator', 'program.list', 'program'))) return;
    const { results } = await env.DB.prepare(
      "SELECT id, platform, handle, name, status FROM bb_programs WHERE status IN ('new','pending_approval') ORDER BY created_at DESC LIMIT 15"
    ).all();
    if (!results || !results.length) {
      return await ctx.reply("🗂️ No programs awaiting review. Discovery runs periodically (<code>/discover</code> to run now), or paste one with <code>/onboard</code>.", { parse_mode: "HTML" });
    }
    const kb = results.map(p => [{
      text: `${p.status === 'pending_approval' ? '🪪' : '🔎'} ${(p.name || p.handle).slice(0, 48)} [${p.platform}]`,
      callback_data: `onboard_review:${p.id}`,
    }]);
    await ctx.reply("🗂️ <b>Discovered / pending programs</b>\nTap one to parse its scope and review for approval:", { parse_mode: "HTML", reply_markup: { inline_keyboard: kb } });
  });

  // Manually trigger a discovery sweep (otherwise the cron runs it periodically).
  bot.command("discover", async (ctx) => {
    await registerUser(ctx);
    if (!(await requireRole(ctx, 'operator', 'program.discover', 'program'))) return;
    const runner = ctx.session?.selected_runner || 'default';
    const jobId = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO scan_jobs (id, command, domain, runner, status, job_type, requested_by_number_id, source) VALUES (?, '--discover --sender-id 0', '', ?, 'pending', 'discover', ?, 'telegram')"
    ).bind(jobId, runner, ctx.from.id).run();
    await ctx.reply("🛰️ <b>Discovery sweep queued.</b> I'll message you when new programs are found, then review them with <code>/programs</code>.", { parse_mode: "HTML" });
  });

  // ----------------------------------------------------
  // Continuous monitoring commands
  // ----------------------------------------------------
  bot.command("monitor", async (ctx) => {
    await registerUser(ctx);
    const raw = (ctx.match || "").trim();
    if (!raw) {
      return await ctx.reply(
        "🛰️ <b>Schedule continuous monitoring</b>\n\n" +
        "Usage: <code>/monitor &lt;target&gt; [interval] [scan_type]</code>\n\n" +
        "• <b>target</b> — domain, company name, or IP/CIDR\n" +
        "• <b>interval</b> — e.g. <code>30m</code>, <code>6h</code>, <code>1d</code> (default <code>1d</code>)\n" +
        "• <b>scan_type</b> — <code>recon</code> | <code>infogather</code> | <code>web</code> | <code>network</code>\n\n" +
        "Example: <code>/monitor example.com 12h infogather</code>",
        { parse_mode: "HTML" }
      );
    }

    const tokens = raw.split(/\s+/);
    const target = tokens.shift();
    const validScans = ["recon", "infogather", "web", "network"];
    const targetType = inferTargetType(target);
    let intervalMinutes = 1440;
    let scanType = targetType === "network" ? "network" : "infogather";

    for (const tok of tokens) {
      if (validScans.includes(tok.toLowerCase())) {
        scanType = tok.toLowerCase();
      } else {
        const parsed = parseInterval(tok);
        if (parsed) intervalMinutes = parsed;
      }
    }

    const id = crypto.randomUUID();
    const nowIso = new Date().toISOString();
    const runner = ctx.session?.selected_runner || "default";
    try {
      await env.DB.prepare(
        "INSERT INTO monitors (id, owner_chat_id, target_type, target, scan_type, runner, interval_minutes, enabled, next_run_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)"
      ).bind(id, ctx.from.id, targetType, target, scanType, runner, intervalMinutes, nowIso).run();
    } catch (err) {
      return await ctx.reply(
        "❌ Could not create monitor. Run <code>/api/db/migrate</code> once if this is a fresh deployment.\n\n" +
        `<code>${escapeHtml(err.message || String(err))}</code>`,
        { parse_mode: "HTML" }
      );
    }

    await ctx.reply(
      "🛰️ <b>Monitor Created</b>\n\n" +
      `• <b>Target:</b> <code>${escapeHtml(target)}</code> (${targetType})\n` +
      `• <b>Scan:</b> <code>${scanType}</code>\n` +
      `• <b>Every:</b> <code>${formatInterval(intervalMinutes)}</code>\n` +
      `• <b>Runner:</b> <code>${runner}</code>\n` +
      `• <b>ID:</b> <code>${id}</code>\n\n` +
      "First run is queued for the next scheduler tick. You'll be alerted on drift — " +
      "new subdomains, ports, TLS certs or cloud assets.",
      { parse_mode: "HTML" }
    );
  });

  bot.command("monitors", async (ctx) => {
    await registerUser(ctx);
    let results = [];
    try {
      const res = await env.DB.prepare(
        "SELECT * FROM monitors WHERE owner_chat_id = ? ORDER BY created_at DESC"
      ).bind(ctx.from.id).all();
      results = res.results || [];
    } catch (err) {
      return await ctx.reply("❌ Could not read monitors: " + escapeHtml(err.message || String(err)), { parse_mode: "HTML" });
    }

    if (results.length === 0) {
      return await ctx.reply(
        "🛰️ No active monitors.\n\nCreate one with <code>/monitor &lt;target&gt; [interval]</code>.",
        { parse_mode: "HTML" }
      );
    }

    let msg = `🛰️ <b>Your Monitors (${results.length})</b>\n`;
    for (const m of results) {
      const state = m.enabled ? "🟢" : "⏸️";
      msg += `\n${state} <code>${escapeHtml(m.target)}</code> · ${m.scan_type} · every ${formatInterval(m.interval_minutes)}\n`;
      msg += `   next: ${m.next_run_at ? escapeHtml(String(m.next_run_at).replace('T', ' ').slice(0, 16)) : 'pending'} · id: <code>${m.id}</code>\n`;
    }
    msg += "\nManage: <code>/unmonitor &lt;id&gt;</code>";
    await ctx.reply(msg, { parse_mode: "HTML" });
  });

  bot.command("unmonitor", async (ctx) => {
    await registerUser(ctx);
    const id = (ctx.match || "").trim();
    if (!id) {
      return await ctx.reply("❌ Usage: <code>/unmonitor &lt;id&gt;</code> (see <code>/monitors</code>)", { parse_mode: "HTML" });
    }
    try {
      const r = await env.DB.prepare(
        "DELETE FROM monitors WHERE id = ? AND owner_chat_id = ?"
      ).bind(id, ctx.from.id).run();
      const removed = r.meta?.changes || r.meta?.rows_written || 0;
      if (!removed) {
        return await ctx.reply("⚠️ No monitor with that ID belongs to you.", { parse_mode: "HTML" });
      }
    } catch (err) {
      return await ctx.reply("❌ Could not remove monitor: " + escapeHtml(err.message || String(err)), { parse_mode: "HTML" });
    }
    await ctx.reply(`🗑️ Monitor <code>${escapeHtml(id)}</code> removed.`, { parse_mode: "HTML" });
  });

  bot.command("vulns", async (ctx) => {
    const args = ctx.match?.trim()?.split(/\s+/) || [];
    const domain = args[0] || null;
    const severity = args[1] || null;

    let query = `
      SELECT f.*, d.host FROM findings f
      JOIN domains d ON f.domain_id = d.id
      LEFT JOIN companies c ON d.company_id = c.id
      WHERE 1=1
    `;
    const binds = [];
    if (domain) {
      query += " AND (lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?))";
      binds.push(domain, domain, domain);
    }
    if (severity) {
      query += " AND lower(f.severity) = lower(?)";
      binds.push(severity);
    }
    query += " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.created_at DESC LIMIT 20";

    const { results: findings } = await env.DB.prepare(query).bind(...binds).all();
    if (!findings.length) {
      return await ctx.reply(`🛡️ No findings found${domain ? ` for <code>${escapeHtml(domain)}</code>` : ''}.`, { parse_mode: "HTML" });
    }

    const emojiMap = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
    const lines = findings.map(f => {
      const em = emojiMap[f.severity.toLowerCase()] || '⚪';
      const cveStr = f.cve ? ` [<code>${escapeHtml(f.cve)}</code>]` : '';
      return `${em} <b>[${escapeHtml(f.severity.toUpperCase())}]</b> ${escapeHtml(f.title)}${cveStr}\n   🔗 <code>${escapeHtml(f.url || f.host)}</code> (<i>${escapeHtml(f.tool)}</i>) - <i>${f.status}</i>`;
    });

    await ctx.reply(
      `🛡️ <b>Vulnerability Findings (${findings.length})</b>\n\n${lines.join('\n\n')}`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🛡️ Open Triage Center", callback_data: "menu_findings" }]]
        }
      }
    );
  });

  bot.command("secrets", async (ctx) => {
    const domain = ctx.match?.trim();
    let query = `
      SELECT s.*, d.host FROM secrets s
      JOIN domains d ON s.domain_id = d.id
      LEFT JOIN companies c ON d.company_id = c.id
      WHERE 1=1
    `;
    const binds = [];
    if (domain) {
      query += " AND (lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?))";
      binds.push(domain, domain, domain);
    }
    query += " ORDER BY s.created_at DESC LIMIT 15";

    const { results: secrets } = await env.DB.prepare(query).bind(...binds).all();
    if (!secrets.length) {
      return await ctx.reply(`🔑 No secrets found${domain ? ` for <code>${escapeHtml(domain)}</code>` : ''}.`, { parse_mode: "HTML" });
    }

    const lines = secrets.map(s => {
      return `🔑 <b>${escapeHtml(s.rule_name)}</b> (<code>${escapeHtml(s.secret_type)}</code>)\n   Snippet: <code>${escapeHtml(s.match_snippet.substring(0, 40))}...</code>\n   File: <code>${escapeHtml(s.file_url || s.host)}</code>`;
    });

    await ctx.reply(
      `🔑 <b>Discovered Secrets (${secrets.length})</b>\n\n${lines.join('\n\n')}`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🔑 Open Secrets Browser", callback_data: "menu_secrets_0" }]]
        }
      }
    );
  });

  bot.command("ports", async (ctx) => {
    const domain = ctx.match?.trim();
    let query = `
      SELECT ns.*, d.host FROM network_services ns
      JOIN domains d ON ns.domain_id = d.id
      LEFT JOIN companies c ON d.company_id = c.id
      WHERE 1=1
    `;
    const binds = [];
    if (domain) {
      query += " AND (lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?))";
      binds.push(domain, domain, domain);
    }
    query += " ORDER BY ns.port ASC LIMIT 30";

    const { results: services } = await env.DB.prepare(query).bind(...binds).all();
    if (!services.length) {
      return await ctx.reply(`🔌 No open ports / services found${domain ? ` for <code>${escapeHtml(domain)}</code>` : ''}.`, { parse_mode: "HTML" });
    }

    const lines = services.map(s => {
      const banner = s.banner ? ` - <i>${escapeHtml(s.banner.substring(0, 30))}</i>` : '';
      return `• <code>${escapeHtml(s.ip)}:${s.port}</code> [${escapeHtml(s.protocol)}] - <b>${escapeHtml(s.service || 'unknown')}</b> ${escapeHtml(s.product || '')} ${escapeHtml(s.version || '')}${banner}`;
    });

    await ctx.reply(
      `🔌 <b>Discovered Services (${services.length})</b>\n\n${lines.join('\n')}`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🔌 Open Services Browser", callback_data: "menu_services_0" }]]
        }
      }
    );
  });

  bot.command("report", async (ctx) => {
    const domain = ctx.match?.trim();
    if (!domain) {
      return await ctx.reply("❌ Usage: <code>/report &lt;domain&gt;</code>", { parse_mode: "HTML" });
    }

    const dom = await env.DB.prepare("SELECT * FROM domains WHERE lower(host) = lower(?)").bind(domain).first();
    const comp = await env.DB.prepare("SELECT * FROM companies WHERE lower(name) = lower(?) OR lower(slug) = lower(?)").bind(domain, domain).first();
    const companyId = dom ? dom.company_id : (comp ? comp.id : null);

    const { results: domains } = await env.DB.prepare("SELECT host FROM domains WHERE company_id = ?").bind(companyId).all();
    const { results: findings } = await env.DB.prepare(`
      SELECT f.* FROM findings f
      JOIN domains d ON f.domain_id = d.id
      WHERE lower(d.host) = lower(?) OR d.company_id = ?
    `).bind(domain, companyId).all();

    const { results: secrets } = await env.DB.prepare(`
      SELECT s.* FROM secrets s
      JOIN domains d ON s.domain_id = d.id
      WHERE lower(d.host) = lower(?) OR d.company_id = ?
    `).bind(domain, companyId).all();

    const { results: services } = await env.DB.prepare(`
      SELECT ns.* FROM network_services ns
      JOIN domains d ON ns.domain_id = d.id
      WHERE lower(d.host) = lower(?) OR d.company_id = ?
    `).bind(domain, companyId).all();

    const crit = findings.filter(f => f.severity?.toLowerCase() === 'critical').length;
    const high = findings.filter(f => f.severity?.toLowerCase() === 'high').length;
    const med = findings.filter(f => f.severity?.toLowerCase() === 'medium').length;
    const low = findings.filter(f => f.severity?.toLowerCase() === 'low').length;
    const info = findings.filter(f => f.severity?.toLowerCase() === 'info').length;

    await ctx.reply(
      `📊 <b>Executive Recon Report: ${escapeHtml(domain)}</b>\n\n` +
      `🌐 <b>Subdomains Discovered:</b> ${domains.length}\n` +
      `🔌 <b>Open Services / Ports:</b> ${services.length}\n` +
      `🔑 <b>Leaked Secrets:</b> ${secrets.length}\n` +
      `🛡️ <b>Vulnerabilities:</b> ${findings.length}\n\n` +
      `<b>Severity Breakdown:</b>\n` +
      `• 🔴 Critical: <b>${crit}</b>\n` +
      `• 🟠 High: <b>${high}</b>\n` +
      `• 🟡 Medium: <b>${med}</b>\n` +
      `• 🔵 Low: <b>${low}</b>\n` +
      `• ⚪ Info: <b>${info}</b>`,
      { parse_mode: "HTML" }
    );
  });

  bot.command("tools", async (ctx) => {
    await ctx.reply(
      `🛠️ <b>cHack Integrated Toolset:</b>\n\n` +
      `• <b>Subdomain & DNS:</b> <code>subfinder</code>, <code>assetfinder</code>, <code>findomain</code>, <code>puredns</code>, <code>dnsx</code>, <code>alterx</code>, <code>scilla</code>, <code>subzy</code>\n` +
      `• <b>Probing & Visual:</b> <code>httpx</code>, <code>gowitness</code>\n` +
      `• <b>Network & Ports:</b> <code>naabu</code>, <code>nmap</code>, <code>massdns</code>\n` +
      `• <b>Crawling & JS:</b> <code>katana</code>, <code>hakrawler</code>, <code>gau</code>, <code>waybackurls</code>, <code>waymore</code>, <code>uro</code>\n` +
      `• <b>Directory & Fuzz:</b> <code>feroxbuster</code>, <code>dirsearch</code>\n` +
      `• <b>Vulnerabilities & DAST:</b> <code>nuclei</code> (v3), <code>dalfox</code>, <code>sqlmap</code>`,
      { parse_mode: "HTML" }
    );
  });

  bot.command("stop", async (ctx) => {
    const jobId = ctx.match?.trim();
    if (!jobId) {
      return await ctx.reply("❌ Usage: <code>/stop &lt;job_id&gt;</code>", { parse_mode: "HTML" });
    }
    await env.DB.prepare("UPDATE scan_jobs SET status = 'failed', stdout = stdout || '\n[CANCELLED BY USER]', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(jobId).run();
    await ctx.reply(`🛑 Job <code>${escapeHtml(jobId)}</code> marked as stopped/cancelled.`, { parse_mode: "HTML" });
  });

  bot.command(["resetdb", "reset"], async (ctx) => {
    await registerUser(ctx);
    if (!await requireRole(ctx, 'superadmin', 'db.reset')) return;
    await ctx.reply(
      `⚠️ <b>DANGER: Reset Cloudflare Database</b>\n\n` +
      `Are you sure you want to permanently delete <b>ALL</b> data in Cloudflare DB?\n\n` +
      `This will delete:\n` +
      `• 🏢 Companies & Scopes\n` +
      `• 🌐 Domains & Subdomains\n` +
      `• 👥 Contacts & People\n` +
      `• 🛡️ Vulnerabilities & Findings\n` +
      `• 🔑 Secrets & Leaks\n` +
      `• 🔌 Open Services & Ports\n` +
      `• 🔗 Discovered Endpoints\n` +
      `• 📜 Scan Jobs Queue & Logs\n` +
      `• 🖥️ Registered Runners\n` +
      `• 👤 Users & Sessions\n\n` +
      `<b>This action is permanent and cannot be undone!</b>`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🔴 Yes, Wipe & Reset All Data", callback_data: "do_reset_db" }
            ],
            [
              { text: "🔙 Cancel", callback_data: "main_menu" }
            ]
          ]
        }
      }
    );
  });

  // ===========================================================================
  // RBAC management commands
  // ===========================================================================

  const VALID_GLOBAL_ROLES = ['pending', 'viewer', 'operator', 'admin'];
  const VALID_TEAM_ROLES = ['viewer', 'operator', 'admin'];

  // Resolve a company by slug or name for membership commands.
  const findCompany = async (q) => env.DB.prepare(
    "SELECT id, name, slug FROM companies WHERE lower(slug) = lower(?) OR lower(name) = lower(?) LIMIT 1"
  ).bind(q, q).first();

  // /whoami — show your identity, role and team memberships (viewer+).
  bot.command("whoami", async (ctx) => {
    const a = ctx.actor || await resolveActor(env, ctx.from);
    let teams = "none";
    if (a.memberships.length) {
      const ids = a.memberships.map((m) => m.company_id);
      const placeholders = ids.map(() => '?').join(',');
      const rows = await env.DB.prepare(
        `SELECT id, name FROM companies WHERE id IN (${placeholders})`
      ).bind(...ids).all();
      const nameById = Object.fromEntries((rows?.results || []).map((r) => [r.id, r.name]));
      teams = a.memberships.map((m) => `${escapeHtml(nameById[m.company_id] || m.company_id)} (${m.role})`).join(", ");
    }
    await ctx.reply(
      `👤 <b>Who am I</b>\n\n` +
      `• <b>Telegram ID:</b> <code>${a.numberId}</code>\n` +
      `• <b>Username:</b> ${escapeHtml(a.username)}\n` +
      `• <b>Global role:</b> <code>${a.role}</code>${a.isSuperadmin ? ' (superadmin via ADMIN_IDS)' : ''}\n` +
      `• <b>Teams:</b> ${teams}`,
      { parse_mode: "HTML" }
    );
  });

  // /users — list registered users and their global roles (admin+).
  bot.command("users", async (ctx) => {
    if (!await requireRole(ctx, 'admin', 'user.list')) return;
    const res = await env.DB.prepare(
      "SELECT username, number_id, role FROM users ORDER BY role DESC, username ASC LIMIT 50"
    ).all();
    const rows = res?.results || [];
    if (!rows.length) return await ctx.reply("No users registered yet.");
    const lines = rows.map((r) =>
      `• <code>${r.number_id}</code> ${escapeHtml(r.username)} — <b>${r.role || 'pending'}</b>`
    );
    await ctx.reply(`👥 <b>Registered Users</b>\n\n${lines.join("\n")}`, { parse_mode: "HTML" });
  });

  // /role <telegram_id> <pending|viewer|operator|admin> — set a global role.
  // admin+ required; only a superadmin may grant/revoke the 'admin' role.
  bot.command("role", async (ctx) => {
    if (!await requireRole(ctx, 'admin', 'role.set')) return;
    const args = (ctx.match || "").trim().split(/\s+/).filter(Boolean);
    if (args.length < 2) {
      return await ctx.reply("❌ Usage: <code>/role &lt;telegram_id&gt; &lt;pending|viewer|operator|admin&gt;</code>", { parse_mode: "HTML" });
    }
    const [idStr, newRole] = args;
    const numberId = Number(idStr);
    if (!Number.isFinite(numberId)) {
      return await ctx.reply("❌ Telegram ID must be numeric.", { parse_mode: "HTML" });
    }
    if (!VALID_GLOBAL_ROLES.includes(newRole)) {
      return await ctx.reply(`❌ Role must be one of: <code>${VALID_GLOBAL_ROLES.join(', ')}</code>`, { parse_mode: "HTML" });
    }
    if (newRole === 'admin' && !ctx.actor.isSuperadmin) {
      return await ctx.reply("⛔ Only a superadmin can grant the <b>admin</b> role.", { parse_mode: "HTML" });
    }
    const target = await env.DB.prepare("SELECT id, username, role FROM users WHERE number_id = ?").bind(numberId).first();
    if (!target) {
      return await ctx.reply(`❌ No registered user with ID <code>${numberId}</code>. Ask them to message the bot once first.`, { parse_mode: "HTML" });
    }
    if (target.role === 'admin' && !ctx.actor.isSuperadmin) {
      return await ctx.reply("⛔ Only a superadmin can change an existing admin's role.", { parse_mode: "HTML" });
    }
    await env.DB.prepare(
      "UPDATE users SET role = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE number_id = ?"
    ).bind(newRole, numberId).run();
    await auditLog(env, {
      actor_user_id: ctx.actor.userId, actor_number_id: ctx.from.id, actor_label: ctx.actor.username,
      source: 'telegram', action: 'role.set', target_type: 'user', target: String(numberId),
      detail: { old_role: target.role, new_role: newRole },
    });
    await ctx.reply(`✅ Global role for <code>${numberId}</code> (${escapeHtml(target.username)}) set to <b>${newRole}</b>.`, { parse_mode: "HTML" });
  });

  // /grant <telegram_id> <company> [viewer|operator|admin] — add team membership.
  bot.command("grant", async (ctx) => {
    if (!await requireRole(ctx, 'admin', 'team.grant')) return;
    const args = (ctx.match || "").trim().split(/\s+/).filter(Boolean);
    if (args.length < 2) {
      return await ctx.reply("❌ Usage: <code>/grant &lt;telegram_id&gt; &lt;company&gt; [viewer|operator|admin]</code>", { parse_mode: "HTML" });
    }
    const numberId = Number(args[0]);
    const role = args[2] && VALID_TEAM_ROLES.includes(args[2]) ? args[2] : 'operator';
    const companyQ = args[1];
    if (!Number.isFinite(numberId)) {
      return await ctx.reply("❌ Telegram ID must be numeric.", { parse_mode: "HTML" });
    }
    const target = await env.DB.prepare("SELECT id, username, role FROM users WHERE number_id = ?").bind(numberId).first();
    if (!target) {
      return await ctx.reply(`❌ No registered user with ID <code>${numberId}</code>. Ask them to message the bot once first.`, { parse_mode: "HTML" });
    }
    const company = await findCompany(companyQ);
    if (!company) {
      return await ctx.reply(`❌ Company <code>${escapeHtml(companyQ)}</code> not found. Create it with /newcompany first.`, { parse_mode: "HTML" });
    }
    await env.DB.prepare(
      `INSERT INTO team_members (id, company_id, user_id, role, created_by)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(company_id, user_id) DO UPDATE SET role = excluded.role`
    ).bind(crypto.randomUUID(), company.id, target.id, role, ctx.actor.userId).run();
    // A viewer/pending user who gains a team membership should be at least a
    // viewer globally so they can sign in; never downgrade a higher role.
    if (roleRank(target.role) < roleRank('viewer')) {
      await env.DB.prepare("UPDATE users SET role = 'viewer' WHERE id = ?").bind(target.id).run();
    }
    await auditLog(env, {
      actor_user_id: ctx.actor.userId, actor_number_id: ctx.from.id, actor_label: ctx.actor.username,
      source: 'telegram', action: 'team.grant', target_type: 'user', target: String(numberId),
      company_id: company.id, detail: { team_role: role, company: company.name },
    });
    await ctx.reply(`✅ <code>${numberId}</code> (${escapeHtml(target.username)}) added to <b>${escapeHtml(company.name)}</b> as <b>${role}</b>.`, { parse_mode: "HTML" });
  });

  // /revoke <telegram_id> <company> — remove team membership.
  bot.command("revoke", async (ctx) => {
    if (!await requireRole(ctx, 'admin', 'team.revoke')) return;
    const args = (ctx.match || "").trim().split(/\s+/).filter(Boolean);
    if (args.length < 2) {
      return await ctx.reply("❌ Usage: <code>/revoke &lt;telegram_id&gt; &lt;company&gt;</code>", { parse_mode: "HTML" });
    }
    const numberId = Number(args[0]);
    const target = await env.DB.prepare("SELECT id, username FROM users WHERE number_id = ?").bind(numberId).first();
    const company = await findCompany(args[1]);
    if (!target || !company) {
      return await ctx.reply("❌ User or company not found.", { parse_mode: "HTML" });
    }
    const res = await env.DB.prepare(
      "DELETE FROM team_members WHERE company_id = ? AND user_id = ?"
    ).bind(company.id, target.id).run();
    await auditLog(env, {
      actor_user_id: ctx.actor.userId, actor_number_id: ctx.from.id, actor_label: ctx.actor.username,
      source: 'telegram', action: 'team.revoke', target_type: 'user', target: String(numberId),
      company_id: company.id, detail: { company: company.name },
    });
    await ctx.reply(`✅ Removed <code>${numberId}</code> from <b>${escapeHtml(company.name)}</b>.`, { parse_mode: "HTML" });
  });

  // /members [company] — list team memberships (admin+).
  bot.command("members", async (ctx) => {
    if (!await requireRole(ctx, 'admin', 'team.list')) return;
    const q = (ctx.match || "").trim();
    let rows;
    if (q) {
      const company = await findCompany(q);
      if (!company) return await ctx.reply(`❌ Company <code>${escapeHtml(q)}</code> not found.`, { parse_mode: "HTML" });
      const res = await env.DB.prepare(
        `SELECT u.number_id, u.username, tm.role, ? AS cname
           FROM team_members tm JOIN users u ON u.id = tm.user_id
          WHERE tm.company_id = ? ORDER BY tm.role DESC`
      ).bind(company.name, company.id).all();
      rows = res?.results || [];
    } else {
      const res = await env.DB.prepare(
        `SELECT u.number_id, u.username, tm.role, c.name AS cname
           FROM team_members tm
           JOIN users u ON u.id = tm.user_id
           JOIN companies c ON c.id = tm.company_id
          ORDER BY c.name ASC, tm.role DESC LIMIT 100`
      ).all();
      rows = res?.results || [];
    }
    if (!rows.length) return await ctx.reply("No team memberships found.");
    const lines = rows.map((r) =>
      `• <b>${escapeHtml(r.cname)}</b> ← <code>${r.number_id}</code> ${escapeHtml(r.username)} (${r.role})`
    );
    await ctx.reply(`🧩 <b>Team Memberships</b>\n\n${lines.join("\n")}`, { parse_mode: "HTML" });
  });

  // /audit [n] — show the last n audit entries (admin+, default 15, max 50).
  bot.command("audit", async (ctx) => {
    if (!await requireRole(ctx, 'admin', 'audit.view')) return;
    let n = parseInt((ctx.match || "").trim(), 10);
    if (!Number.isFinite(n) || n <= 0) n = 15;
    n = Math.min(n, 50);
    const res = await env.DB.prepare(
      "SELECT ts, actor_label, actor_number_id, source, action, decision, target_type, target FROM audit_log ORDER BY ts DESC LIMIT ?"
    ).bind(n).all();
    const rows = res?.results || [];
    if (!rows.length) return await ctx.reply("Audit log is empty.");
    const lines = rows.map((r) => {
      const icon = r.decision === 'deny' ? '⛔' : '✅';
      const who = r.actor_label || `id:${r.actor_number_id}`;
      const tgt = r.target ? ` <code>${escapeHtml(String(r.target))}</code>` : '';
      const when = String(r.ts).replace('T', ' ').replace('Z', '').slice(5, 19);
      return `${icon} <code>${when}</code> ${escapeHtml(who)} [${r.source}] <b>${r.action}</b>${tgt}`;
    });
    await ctx.reply(`📜 <b>Audit Log</b> (last ${rows.length})\n\n${lines.join("\n")}`, { parse_mode: "HTML" });
  });

  // ---- Team workflows ----
  bot.command(["campaigns", "engagements"], async (ctx) => {
    await registerUser(ctx);
    const { results } = await env.DB.prepare("SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 20").all();
    if (!results.length) {
      return await ctx.reply("📋 <b>Campaigns</b>\n\nNone yet. Create one with:\n<code>/newcampaign Acme Pentest | engagement</code>", { parse_mode: "HTML" });
    }
    const statusBadge = { prospect: "🔆", active: "🟢", paused: "⏸️", won: "🏆", lost: "💤", closed: "📦" };
    const lines = results.map((c) => {
      const b = statusBadge[c.status] || "•";
      const auth = c.authorized ? "🔓 authorized" : "🔒 unauthorized";
      return `${b} <b>${escapeHtml(c.name)}</b> <code>${escapeHtml(c.slug || c.id)}</code>\n   ${escapeHtml(c.kind)} · ${escapeHtml(c.status)} · ${auth}`;
    });
    await ctx.reply(`📋 <b>Campaigns (${results.length})</b>\n\n${lines.join("\n")}`, { parse_mode: "HTML" });
  });

  bot.command(["newcampaign", "newengagement"], async (ctx) => {
    await registerUser(ctx);
    const raw = (ctx.match || "").trim();
    if (!raw) {
      return await ctx.reply("Usage: <code>/newcampaign &lt;name&gt; | &lt;engagement|acquisition&gt;</code>", { parse_mode: "HTML" });
    }
    const [namePart, kindPart] = raw.split("|").map((s) => s.trim());
    const kind = (kindPart || "engagement").toLowerCase() === "acquisition" ? "acquisition" : "engagement";
    const userRow = await env.DB.prepare("SELECT id FROM users WHERE number_id = ?").bind(ctx.from.id).first();
    const id = crypto.randomUUID();
    const slug = slugify(namePart);
    await env.DB.prepare(
      `INSERT INTO campaigns (id, name, slug, owner_user_id, kind, status) VALUES (?, ?, ?, ?, ?, 'prospect')`
    ).bind(id, namePart, slug, userRow?.id || null, kind).run();
    if (userRow?.id) {
      await env.DB.prepare("INSERT OR IGNORE INTO campaign_members (campaign_id, user_id, role) VALUES (?, ?, 'lead')").bind(id, userRow.id).run();
    }
    await ctx.reply(`✅ Campaign created: <b>${escapeHtml(namePart)}</b> (<code>${escapeHtml(slug)}</code>, ${kind}).\n\n⚠️ Mark it authorized before running playbooks against its scope.`, { parse_mode: "HTML" });
  });

  bot.command(["groups", "targetgroups"], async (ctx) => {
    await registerUser(ctx);
    const { results } = await env.DB.prepare(
      `SELECT g.*, (SELECT COUNT(*) FROM target_group_members m WHERE m.group_id = g.id) AS n
       FROM target_groups g ORDER BY g.created_at DESC LIMIT 20`
    ).all();
    if (!results.length) return await ctx.reply("🎯 <b>Target groups</b>\n\nNone yet.", { parse_mode: "HTML" });
    const lines = results.map((g) => `🎯 <b>${escapeHtml(g.name)}</b> <code>${escapeHtml(g.id)}</code>\n   ${g.n} target(s) · ${escapeHtml(g.visibility)}`);
    await ctx.reply(`🎯 <b>Target groups (${results.length})</b>\n\n${lines.join("\n")}`, { parse_mode: "HTML" });
  });

  bot.command("templates", async (ctx) => {
    await registerUser(ctx);
    const { results } = await env.DB.prepare("SELECT * FROM job_templates ORDER BY created_at DESC LIMIT 20").all();
    if (!results.length) return await ctx.reply("🧩 <b>Job templates</b>\n\nNone yet.", { parse_mode: "HTML" });
    const lines = results.map((t) => `🧩 <b>${escapeHtml(t.name)}</b> <code>${escapeHtml(t.slug || t.id)}</code>\n   <code>${escapeHtml(t.command_template)}</code>`);
    await ctx.reply(`🧩 <b>Job templates (${results.length})</b>\n\n${lines.join("\n")}`, { parse_mode: "HTML" });
  });

  bot.command("playbooks", async (ctx) => {
    await registerUser(ctx);
    const { results } = await env.DB.prepare(
      `SELECT p.*, (SELECT COUNT(*) FROM playbook_steps s WHERE s.playbook_id = p.id) AS steps
       FROM playbooks p ORDER BY p.created_at DESC LIMIT 20`
    ).all();
    if (!results.length) return await ctx.reply("📘 <b>Playbooks</b>\n\nNone yet.", { parse_mode: "HTML" });
    const lines = results.map((p) => `📘 <b>${escapeHtml(p.name)}</b> <code>${escapeHtml(p.slug || p.id)}</code>\n   ${p.steps} step(s)`);
    await ctx.reply(`📘 <b>Playbooks (${results.length})</b>\n\nRun one with <code>/runplaybook &lt;slug&gt; &lt;target&gt;</code>\n\n${lines.join("\n")}`, { parse_mode: "HTML" });
  });

  bot.command("runplaybook", async (ctx) => {
    await registerUser(ctx);
    const parts = (ctx.match || "").trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
      return await ctx.reply("Usage: <code>/runplaybook &lt;playbook-slug-or-id&gt; &lt;target&gt;</code>", { parse_mode: "HTML" });
    }
    const [ref, target] = parts;
    let safeTarget;
    try {
      safeTarget = assertSafeTarget(target);
    } catch (e) {
      return await ctx.reply("🛑 Invalid target: it must be a bare host/domain with no spaces or shell characters.");
    }
    const pb = await env.DB.prepare("SELECT * FROM playbooks WHERE id = ? OR slug = ?").bind(ref, ref).first();
    if (!pb) return await ctx.reply(`🛑 Playbook not found: <code>${escapeHtml(ref)}</code>`, { parse_mode: "HTML" });

    if (pb.campaign_id) {
      const camp = await env.DB.prepare("SELECT name, authorized FROM campaigns WHERE id = ?").bind(pb.campaign_id).first();
      if (camp && !camp.authorized) {
        return await ctx.reply(`🔒 Campaign <b>${escapeHtml(camp.name)}</b> is not marked authorized. Refusing to launch scans until scope is confirmed.`, { parse_mode: "HTML" });
      }
    }

    const { results: steps } = await env.DB.prepare(
      "SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_order ASC"
    ).bind(pb.id).all();
    if (!steps.length) return await ctx.reply("🛑 This playbook has no steps yet.");

    const sender = String(ctx.from.id);
    const jobIds = [];
    for (const st of steps) {
      let command;
      let runner = 'default';
      if (st.template_id) {
        const tpl = await env.DB.prepare("SELECT * FROM job_templates WHERE id = ?").bind(st.template_id).first();
        if (tpl) { command = expandCommandTemplate(tpl.command_template, safeTarget, sender); runner = tpl.runner || 'default'; }
      }
      if (!command) command = commandForPhase(st.phase, safeTarget, sender);
      jobIds.push(await queueJob(env, command, safeTarget, runner));
    }
    await ctx.reply(`🚀 Queued <b>${jobIds.length}</b> job(s) from <b>${escapeHtml(pb.name)}</b> against <code>${escapeHtml(safeTarget)}</code>.\n\nTrack them with /queue.`, { parse_mode: "HTML" });
  });

  // ---- Admin Control Center (/admin) ----
  const roleIcon = (r) => ({ superadmin: '👑', admin: '🛡️', operator: '🔧', viewer: '👁️', pending: '⏳' }[r] || '•');

  const ADMIN_MENU_TEXT =
    "🛡️ <b>Admin Control Center</b>\n\n" +
    "Full management surface — access control, operations, assets, workflows and audit. " +
    "Every action is role-checked and written to the tamper-evident audit log.";

  const buildAdminMenu = () => ({
    inline_keyboard: [
      [{ text: "👥 Users & Roles", callback_data: "admin_users" },
       { text: "🧑‍🤝‍🧑 Team Memberships", callback_data: "admin_members" }],
      [{ text: "📊 Dashboard", callback_data: "menu_dashboard" },
       { text: "📜 Scan Queue", callback_data: "view_new_domains" },
       { text: "🖥️ Runners", callback_data: "change_runner" }],
      [{ text: "🎯 Targets", callback_data: "view_targets_0" },
       { text: "👤 Contacts", callback_data: "view_contacts_0" }],
      [{ text: "🛡️ Findings", callback_data: "menu_findings" },
       { text: "🔑 Secrets", callback_data: "menu_secrets_0" },
       { text: "🔌 Services", callback_data: "menu_services_0" }],
      [{ text: "📋 Campaigns", callback_data: "admin_campaigns" },
       { text: "🧩 Templates", callback_data: "admin_templates" },
       { text: "📘 Playbooks", callback_data: "admin_playbooks" }],
      [{ text: "🧾 Audit Log", callback_data: "admin_audit" }],
      [{ text: "⚠️ Reset Database", callback_data: "confirm_reset_db" }],
      [{ text: "🔙 Main Menu", callback_data: "main_menu" }],
    ],
  });

  // Callbacks only clear the "viewer" gate, so every admin-only panel must
  // re-check the role here. Returns the actor when allowed, else null (and
  // replaces the message with a denial).
  const ensureAdminCallback = async (ctx) => {
    const actor = ctx.actor || await resolveActor(env, ctx.from);
    if (actor.hasGlobal('admin')) return actor;
    await auditLog(env, {
      actor_user_id: actor.userId, actor_number_id: ctx.from?.id || 0, actor_label: actor.username,
      source: 'telegram', action: 'admin.panel', decision: 'deny',
      target_type: 'callback', target: ctx.callbackQuery?.data || null,
      detail: { role: actor.role },
    });
    await safeEditMessageText(ctx, "⛔ <b>Admins only.</b>\n\nThis panel requires the <b>admin</b> role.", {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: "🔙 Main Menu", callback_data: "main_menu" }]] },
    }).catch(() => {});
    return null;
  };

  const renderAdminUsers = async (ctx) => {
    const res = await env.DB.prepare(
      "SELECT username, number_id, role FROM users ORDER BY role DESC, username ASC LIMIT 50"
    ).all();
    const rows = res?.results || [];
    const kb = rows.slice(0, 20).map((r) => ([{
      text: `${roleIcon(r.role)} ${r.username} · ${r.role || 'pending'}`,
      callback_data: `admin_user:${r.number_id}`,
    }]));
    kb.push([{ text: "🔄 Refresh", callback_data: "admin_users" }, { text: "🔙 Admin", callback_data: "admin_home" }]);
    const text = rows.length
      ? `👥 <b>Users &amp; Roles (${rows.length})</b>\n\nTap a user to change their global role.`
      : "👥 <b>Users &amp; Roles</b>\n\nNo users registered yet.";
    await safeEditMessageText(ctx, text, { parse_mode: "HTML", reply_markup: { inline_keyboard: kb } });
  };

  const renderAdminUserPanel = async (ctx, numberId) => {
    const u = await env.DB.prepare("SELECT username, number_id, role FROM users WHERE number_id = ?").bind(numberId).first();
    if (!u) {
      return await safeEditMessageText(ctx, "User not found.", {
        parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙 Users", callback_data: "admin_users" }]] },
      });
    }
    const roleBtns = VALID_GLOBAL_ROLES.map((r) => ({
      text: (u.role === r ? "✅ " : "") + roleIcon(r) + " " + r,
      callback_data: `admin_setrole:${numberId}:${r}`,
    }));
    const kb = [];
    for (let i = 0; i < roleBtns.length; i += 2) kb.push(roleBtns.slice(i, i + 2));
    kb.push([{ text: "🔙 Users", callback_data: "admin_users" }]);
    const text =
      `👤 <b>${escapeHtml(u.username)}</b>\n` +
      `• Telegram ID: <code>${u.number_id}</code>\n` +
      `• Current role: <b>${u.role || 'pending'}</b>\n\n` +
      `Select a new global role (only a superadmin may grant/change <b>admin</b>):`;
    await safeEditMessageText(ctx, text, { parse_mode: "HTML", reply_markup: { inline_keyboard: kb } });
  };

  // Shared with /role: same validation, superadmin guard and audit trail.
  const applyAdminSetRole = async (ctx, actor, numberId, newRole) => {
    if (!VALID_GLOBAL_ROLES.includes(newRole)) {
      return await ctx.answerCallbackQuery({ text: "Invalid role.", show_alert: true }).catch(() => {});
    }
    if (newRole === 'admin' && !actor.isSuperadmin) {
      return await safeEditMessageText(ctx, "⛔ Only a superadmin can grant the <b>admin</b> role.", {
        parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙 Users", callback_data: "admin_users" }]] },
      });
    }
    const target = await env.DB.prepare("SELECT id, username, role FROM users WHERE number_id = ?").bind(numberId).first();
    if (!target) {
      return await safeEditMessageText(ctx, "❌ User no longer exists.", {
        parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙 Users", callback_data: "admin_users" }]] },
      });
    }
    if (target.role === 'admin' && !actor.isSuperadmin) {
      return await safeEditMessageText(ctx, "⛔ Only a superadmin can change an existing admin's role.", {
        parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "🔙 Users", callback_data: "admin_users" }]] },
      });
    }
    await env.DB.prepare(
      "UPDATE users SET role = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE number_id = ?"
    ).bind(newRole, numberId).run();
    await auditLog(env, {
      actor_user_id: actor.userId, actor_number_id: ctx.from.id, actor_label: actor.username,
      source: 'telegram', action: 'role.set', target_type: 'user', target: String(numberId),
      detail: { old_role: target.role, new_role: newRole, via: 'admin-dashboard' },
    });
    await renderAdminUserPanel(ctx, numberId);
  };

  const renderAdminAudit = async (ctx) => {
    const res = await env.DB.prepare(
      "SELECT ts, actor_label, actor_number_id, source, action, decision, target_type, target FROM audit_log ORDER BY ts DESC LIMIT 15"
    ).all();
    const rows = res?.results || [];
    const body = rows.length
      ? rows.map((r) => {
          const icon = r.decision === 'deny' ? '⛔' : '✅';
          const who = r.actor_label || `id:${r.actor_number_id}`;
          const tgt = r.target ? ` <code>${escapeHtml(String(r.target))}</code>` : '';
          const when = String(r.ts).replace('T', ' ').replace('Z', '').slice(5, 19);
          return `${icon} <code>${when}</code> ${escapeHtml(who)} [${r.source}] <b>${r.action}</b>${tgt}`;
        }).join("\n")
      : "Audit log is empty.";
    await safeEditMessageText(ctx, `🧾 <b>Audit Log</b> (last ${rows.length})\n\n${body}`, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: "🔄 Refresh", callback_data: "admin_audit" }, { text: "🔙 Admin", callback_data: "admin_home" }]] },
    });
  };

  const renderAdminMembers = async (ctx) => {
    const res = await env.DB.prepare(
      `SELECT u.number_id, u.username, tm.role, c.name AS cname
         FROM team_members tm
         JOIN users u ON u.id = tm.user_id
         JOIN companies c ON c.id = tm.company_id
        ORDER BY c.name ASC, tm.role DESC LIMIT 100`
    ).all();
    const rows = res?.results || [];
    const body = rows.length
      ? rows.map((r) => `• <b>${escapeHtml(r.cname)}</b> ← <code>${r.number_id}</code> ${escapeHtml(r.username)} (${r.role})`).join("\n")
      : "No team memberships yet. Grant one with <code>/grant &lt;id&gt; &lt;company&gt; [role]</code>.";
    await safeEditMessageText(ctx, `🧑‍🤝‍🧑 <b>Team Memberships</b>\n\n${body}`, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: "🔄 Refresh", callback_data: "admin_members" }, { text: "🔙 Admin", callback_data: "admin_home" }]] },
    });
  };

  const renderAdminList = async (ctx, kind) => {
    let text;
    if (kind === 'campaigns') {
      const { results } = await env.DB.prepare("SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 20").all();
      const badge = { prospect: "🔆", active: "🟢", paused: "⏸️", won: "🏆", lost: "💤", closed: "📦" };
      text = results.length
        ? `📋 <b>Campaigns (${results.length})</b>\n\n` + results.map((c) =>
            `${badge[c.status] || "•"} <b>${escapeHtml(c.name)}</b> <code>${escapeHtml(c.slug || c.id)}</code>\n   ${escapeHtml(c.kind)} · ${escapeHtml(c.status)} · ${c.authorized ? "🔓 authorized" : "🔒 unauthorized"}`
          ).join("\n")
        : "📋 <b>Campaigns</b>\n\nNone yet. Create one with <code>/newcampaign &lt;name&gt; | &lt;kind&gt;</code>.";
    } else if (kind === 'templates') {
      const { results } = await env.DB.prepare("SELECT * FROM job_templates ORDER BY created_at DESC LIMIT 20").all();
      text = results.length
        ? `🧩 <b>Job Templates (${results.length})</b>\n\n` + results.map((t) =>
            `🧩 <b>${escapeHtml(t.name)}</b> <code>${escapeHtml(t.slug || t.id)}</code>\n   <code>${escapeHtml(t.command_template)}</code>`
          ).join("\n")
        : "🧩 <b>Job Templates</b>\n\nNone yet.";
    } else {
      const { results } = await env.DB.prepare(
        `SELECT p.*, (SELECT COUNT(*) FROM playbook_steps s WHERE s.playbook_id = p.id) AS steps
         FROM playbooks p ORDER BY p.created_at DESC LIMIT 20`
      ).all();
      text = results.length
        ? `📘 <b>Playbooks (${results.length})</b>\n\nRun with <code>/runplaybook &lt;slug&gt; &lt;target&gt;</code>\n\n` + results.map((p) =>
            `📘 <b>${escapeHtml(p.name)}</b> <code>${escapeHtml(p.slug || p.id)}</code>\n   ${p.steps} step(s)`
          ).join("\n")
        : "📘 <b>Playbooks</b>\n\nNone yet.";
    }
    await safeEditMessageText(ctx, text, {
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: "🔙 Admin", callback_data: "admin_home" }]] },
    });
  };

  // /admin — open the Admin Control Center. Admin role required.
  bot.command("admin", async (ctx) => {
    if (!await requireRole(ctx, 'admin', 'admin.dashboard')) return;
    await ctx.reply(ADMIN_MENU_TEXT, { parse_mode: "HTML", reply_markup: buildAdminMenu() });
  });

  bot.command("help", async (ctx) => {
    await ctx.reply(
      `📖 <b>cHack Bot Command & Management Guide</b>\n\n` +
      `<b>Navigation & Dashboard:</b>\n` +
      `• <code>/menu</code> or <code>/start</code> - Open interactive Main Menu\n` +
      `• <code>/dashboard</code> or <code>/stats</code> - System stats & asset counts\n` +
      `• <code>/resetdb</code> - Wipe & reset Cloudflare DB\n` +
      `• <code>/help</code> - Show this guide\n\n` +
      `<b>Program Onboarding & Discovery:</b>\n` +
      `• <code>/programs</code> - Review discovered programs & approve scope\n` +
      `• <code>/discover</code> - Sweep platforms (YesWeHack, Bugcrowd) now\n` +
      `• <code>/onboard &lt;platform&gt; &lt;handle&gt;</code> - Onboard from pasted scope\n` +
      `  <i>Every new program's scope is approved by you before any scan.</i>\n\n` +
      `<b>Targets & Assets Management:</b>\n` +
      `• <code>/targets</code> - Interactive target companies list\n` +
      `• <code>/contacts</code> - Interactive contacts/leads list\n` +
      `• <code>/newcompany</code> - Add a new company target\n` +
      `• <code>/newperson</code> - Add a new person contact\n` +
      `• <code>/delcompany &lt;name&gt;</code> - Delete company\n` +
      `• <code>/deldomain &lt;host&gt;</code> - Delete domain\n` +
      `• <code>/delperson &lt;name&gt;</code> - Delete person\n\n` +
      `<b>Scans & Queue Management:</b>\n` +
      `• <code>/queue</code> or <code>/jobs</code> - Manage running & pending scans\n` +
      `• <code>/recon &lt;domain&gt;</code> - Launch 5-phase full recon\n` +
      `• <code>/infogather &lt;domain&gt;</code> - Subdomain & live probing\n` +
      `• <code>/web &lt;domain&gt;</code> - Web crawling & endpoint discovery\n` +
      `• <code>/network &lt;target&gt;</code> - Port & service scan\n` +
      `• <code>/stop &lt;job_id&gt;</code> - Terminate a running scan\n` +
      `• <code>/clean</code> - Clean finished jobs from queue\n\n` +
      `<b>Findings & Intelligence:</b>\n` +
      `• <code>/vulns [domain] [severity]</code> - Search vulnerabilities\n` +
      `• <code>/secrets [domain]</code> - Search discovered secrets\n` +
      `• <code>/ports [domain]</code> - Search open services\n` +
      `• <code>/report &lt;domain&gt;</code> - Executive summary report\n\n` +
      `<b>Continuous Monitoring:</b>\n` +
      `• <code>/monitor &lt;target&gt; [interval] [type]</code> - Schedule recurring scans\n` +
      `• <code>/monitors</code> - List your active monitors\n` +
      `• <code>/unmonitor &lt;id&gt;</code> - Remove a monitor\n\n` +
      `<b>Access Control & Audit:</b>\n` +
      `• <code>/admin</code> - Open the Admin Control Center dashboard <i>(admin)</i>\n` +
      `• <code>/whoami</code> - Your ID, role & team memberships\n` +
      `• <code>/users</code> - List users & roles <i>(admin)</i>\n` +
      `• <code>/role &lt;id&gt; &lt;role&gt;</code> - Set global role <i>(admin)</i>\n` +
      `• <code>/grant &lt;id&gt; &lt;company&gt; [role]</code> - Add to team <i>(admin)</i>\n` +
      `• <code>/revoke &lt;id&gt; &lt;company&gt;</code> - Remove from team <i>(admin)</i>\n` +
      `• <code>/members [company]</code> - List team memberships <i>(admin)</i>\n` +
      `• <code>/audit [n]</code> - Recent audit log <i>(admin)</i>\n\n` +
      `<b>Team Workflows:</b>\n` +
      `• <code>/campaigns</code> - List client/acquisition campaigns\n` +
      `• <code>/newcampaign &lt;name&gt; | &lt;kind&gt;</code> - Create a campaign\n` +
      `• <code>/groups</code> - List shared target groups\n` +
      `• <code>/templates</code> - List job templates\n` +
      `• <code>/playbooks</code> - List per-target playbooks\n` +
      `• <code>/runplaybook &lt;slug&gt; &lt;target&gt;</code> - Expand a playbook into jobs\n\n` +
      `<i>Roles: viewer (read) → operator (scan in-scope) → admin (manage) → superadmin (ADMIN_IDS).</i>`,
      { parse_mode: "HTML" }
    );
  });

  // ----------------------------------------------------
  // Bot Interactive Callback Query Handlers
  // ----------------------------------------------------
  bot.on("callback_query:data", async (ctx) => {
    const data = ctx.callbackQuery.data;
    await registerUser(ctx);

    // Main Menu & Navigation
    if (data === "main_menu") {
      ctx.session.step = 'MAIN_MENU';
      const menuMarkup = await createMainMenu(ctx, env);
      await safeEditMessageText(ctx, "🛰️ <b>cHack C2 Control Center</b>\n\nSelect an option below to manage targets, scans, or findings:", {
        parse_mode: "HTML",
        reply_markup: menuMarkup
      });
    } else if (data === "cancel") {
      ctx.session.step = 'MAIN_MENU';
      const menuMarkup = await createMainMenu(ctx, env);
      await safeEditMessageText(ctx, "❌ Action cancelled. Select an option from the menu:", {
        parse_mode: "HTML",
        reply_markup: menuMarkup
      });
    } else if (data.startsWith("onboard_ok:")) {
      if (!(await requireRole(ctx, 'operator', 'program.apply', 'program'))) return;
      const pid = data.slice("onboard_ok:".length);
      const prog = await env.DB.prepare("SELECT * FROM bb_programs WHERE id = ?").bind(pid).first();
      if (!prog) { await ctx.answerCallbackQuery({ text: "Program not found", show_alert: true }).catch(() => {}); return; }
      const runner = ctx.session?.selected_runner || 'default';
      const jobId = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO scan_jobs (id, command, domain, runner, status, job_type, requested_by_number_id, source) VALUES (?, ?, '', ?, 'pending', 'onboard', ?, 'telegram')"
      ).bind(jobId, `--onboard-apply-remote ${pid} --sender-id ${ctx.from.id}`, runner, ctx.from.id).run();
      await env.DB.prepare("UPDATE pending_approvals SET status='approved', decided_by=?, decided_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE program_id=? AND status='pending'").bind(ctx.from.id, pid).run();
      await auditLog(env, { actor_number_id: ctx.from.id, actor_label: ctx.from.username, source: 'telegram', action: 'program.apply', decision: 'allow', target_type: 'program', target: prog.handle || prog.name, detail: { program_id: pid, job_id: jobId } });
      await ctx.answerCallbackQuery({ text: "Approved — writing scope.txt on the runner" }).catch(() => {});
      await safeEditMessageText(ctx, `✅ <b>Approved</b> <code>${escapeHtml(prog.handle || prog.name || pid)}</code>\n\nThe runner is appending the approved hosts to <code>scope.txt</code>, then monitoring will pick them up.`, { parse_mode: "HTML" });
    } else if (data.startsWith("onboard_review:")) {
      if (!(await requireRole(ctx, 'operator', 'program.onboard', 'program'))) return;
      const pid = data.slice("onboard_review:".length);
      const prog = await env.DB.prepare("SELECT * FROM bb_programs WHERE id = ?").bind(pid).first();
      if (!prog) { await ctx.answerCallbackQuery({ text: "Program not found", show_alert: true }).catch(() => {}); return; }
      if (!prog.scope_raw) {
        await ctx.answerCallbackQuery({ text: "No auto-scope — onboard manually", show_alert: true }).catch(() => {});
        await ctx.reply(`ℹ️ <b>${escapeHtml(prog.name || prog.handle)}</b> has no machine-readable scope (that platform needs auth). Onboard it manually:\n<code>/onboard ${escapeHtml(prog.platform)} ${escapeHtml(prog.handle)}</code>\nthen paste its scope text.`, { parse_mode: "HTML" });
        return;
      }
      // Route the resulting gate back to whoever tapped review.
      await env.DB.prepare("UPDATE bb_programs SET created_by=? WHERE id=?").bind(ctx.from.id, pid).run();
      const runner = ctx.session?.selected_runner || 'default';
      const jobId = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO scan_jobs (id, command, domain, runner, status, job_type, requested_by_number_id, source) VALUES (?, ?, '', ?, 'pending', 'onboard', ?, 'telegram')"
      ).bind(jobId, `--onboard-process ${pid} --sender-id ${ctx.from.id}`, runner, ctx.from.id).run();
      await ctx.answerCallbackQuery({ text: "Parsing scope…" }).catch(() => {});
      await safeEditMessageText(ctx, `🔎 Parsing <code>${escapeHtml(prog.name || prog.handle)}</code> [${escapeHtml(prog.platform)}]… I'll send the proposed scope to approve.`, { parse_mode: "HTML" });
    } else if (data.startsWith("onboard_no:")) {
      if (!(await requireRole(ctx, 'operator', 'program.skip', 'program'))) return;
      const pid = data.slice("onboard_no:".length);
      const prog = await env.DB.prepare("SELECT handle, name FROM bb_programs WHERE id = ?").bind(pid).first();
      await env.DB.prepare("UPDATE bb_programs SET status='skipped', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?").bind(pid).run();
      await env.DB.prepare("UPDATE pending_approvals SET status='skipped', decided_by=?, decided_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE program_id=? AND status='pending'").bind(ctx.from.id, pid).run();
      await auditLog(env, { actor_number_id: ctx.from.id, actor_label: ctx.from.username, source: 'telegram', action: 'program.skip', decision: 'allow', target_type: 'program', target: (prog && (prog.handle || prog.name)) || pid, detail: { program_id: pid } });
      await ctx.answerCallbackQuery({ text: "Skipped" }).catch(() => {});
      await safeEditMessageText(ctx, `🚫 <b>Skipped</b> <code>${escapeHtml((prog && (prog.handle || prog.name)) || pid)}</code>. Nothing was added to scope.`, { parse_mode: "HTML" });
    } else if (data === "admin_home") {
      if (!await ensureAdminCallback(ctx)) return;
      await safeEditMessageText(ctx, ADMIN_MENU_TEXT, { parse_mode: "HTML", reply_markup: buildAdminMenu() });
    } else if (data === "admin_users") {
      if (!await ensureAdminCallback(ctx)) return;
      await renderAdminUsers(ctx);
    } else if (data.startsWith("admin_user:")) {
      if (!await ensureAdminCallback(ctx)) return;
      const numberId = Number(data.split(":")[1]);
      if (Number.isFinite(numberId)) await renderAdminUserPanel(ctx, numberId);
    } else if (data.startsWith("admin_setrole:")) {
      const actor = await ensureAdminCallback(ctx);
      if (!actor) return;
      const [, idStr, newRole] = data.split(":");
      const numberId = Number(idStr);
      if (Number.isFinite(numberId)) await applyAdminSetRole(ctx, actor, numberId, newRole);
    } else if (data === "admin_members") {
      if (!await ensureAdminCallback(ctx)) return;
      await renderAdminMembers(ctx);
    } else if (data === "admin_audit") {
      if (!await ensureAdminCallback(ctx)) return;
      await renderAdminAudit(ctx);
    } else if (data === "admin_campaigns") {
      if (!await ensureAdminCallback(ctx)) return;
      await renderAdminList(ctx, 'campaigns');
    } else if (data === "admin_templates") {
      if (!await ensureAdminCallback(ctx)) return;
      await renderAdminList(ctx, 'templates');
    } else if (data === "admin_playbooks") {
      if (!await ensureAdminCallback(ctx)) return;
      await renderAdminList(ctx, 'playbooks');
    } else if (data === "menu_dashboard") {
      try {
        const compCount = (await env.DB.prepare("SELECT count(*) as cnt FROM companies").first())?.cnt || 0;
        const domCount = (await env.DB.prepare("SELECT count(*) as cnt FROM domains").first())?.cnt || 0;
        const peopleCount = (await env.DB.prepare("SELECT count(*) as cnt FROM people").first())?.cnt || 0;
        
        const { results: findings } = await env.DB.prepare("SELECT severity, status FROM findings").all();
        const crit = findings.filter(f => f.severity?.toLowerCase() === 'critical').length;
        const high = findings.filter(f => f.severity?.toLowerCase() === 'high').length;
        const med = findings.filter(f => f.severity?.toLowerCase() === 'medium').length;
        const low = findings.filter(f => f.severity?.toLowerCase() === 'low').length;
        const info = findings.filter(f => f.severity?.toLowerCase() === 'info').length;
        const resolved = findings.filter(f => f.status === 'resolved').length;

        const secretsCount = (await env.DB.prepare("SELECT count(*) as cnt FROM secrets").first())?.cnt || 0;
        const servicesCount = (await env.DB.prepare("SELECT count(*) as cnt FROM network_services").first())?.cnt || 0;
        const runningJobs = (await env.DB.prepare("SELECT count(*) as cnt FROM scan_jobs WHERE status IN ('pending', 'running')").first())?.cnt || 0;
        
        const cutoff = Math.floor(Date.now() / 1000) - 60;
        const onlineRunners = (await env.DB.prepare("SELECT count(*) as cnt FROM runners WHERE last_seen >= ?").bind(cutoff).first())?.cnt || 0;
        const totalRunners = (await env.DB.prepare("SELECT count(*) as cnt FROM runners").first())?.cnt || 0;

        const text =
          `📊 <b>cHack Intelligence & Management Dashboard</b>\n\n` +
          `🎯 <b>Targets & Assets:</b>\n` +
          `• 🏢 Companies / Scopes: <b>${compCount}</b>\n` +
          `• 🌐 Domains / Subdomains: <b>${domCount}</b>\n` +
          `• 👥 Contacts & People: <b>${peopleCount}</b>\n\n` +
          `🛡️ <b>Findings & Vulnerabilities (${findings.length}):</b>\n` +
          `• 🔴 Critical: <b>${crit}</b>\n` +
          `• 🟠 High: <b>${high}</b>\n` +
          `• 🟡 Medium: <b>${med}</b>\n` +
          `• 🔵 Low: <b>${low}</b>\n` +
          `• ⚪ Info: <b>${info}</b>\n` +
          `• ✅ Resolved / Fixed: <b>${resolved}</b>\n\n` +
          `🔑 <b>Secrets & Leaks:</b> <b>${secretsCount}</b>\n` +
          `🔌 <b>Network Services & Open Ports:</b> <b>${servicesCount}</b>\n\n` +
          `⚙️ <b>System & Infrastructure:</b>\n` +
          `• ⏳ Active / Queued Jobs: <b>${runningJobs}</b>\n` +
          `• 🖥️ Runners Online: <b>${onlineRunners} / ${totalRunners}</b>`;

        await safeEditMessageText(ctx, text, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [
                { text: "🔄 Refresh", callback_data: "menu_dashboard" },
                { text: "🧹 Clear Finished Jobs", callback_data: "action_clean_queue" }
              ],
              [
                { text: "🎯 Targets", callback_data: "view_targets_0" },
                { text: "🛡️ Triage Findings", callback_data: "menu_findings" }
              ],
              [
                { text: "⚠️ Reset Database", callback_data: "confirm_reset_db" },
                { text: "🔙 Main Menu", callback_data: "main_menu" }
              ]
            ]
          }
        });
      } catch (err) {
        await ctx.reply(`❌ Error loading dashboard: ${escapeHtml(err.message)}`);
      }
    } else if (data === "menu_scan") {
      await safeEditMessageText(ctx, "🚀 <b>Launch Reconnaissance Scan</b>\n\nSelect the type of reconnaissance or scanning operation to execute:", {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🏢 Full Recon (Company / Domain)", callback_data: "target_company" }
            ],
            [
              { text: "🔍 Fast Info-Gathering", callback_data: "launch_infogather" },
              { text: "🌐 Web Crawl & URLs", callback_data: "launch_web_scan" }
            ],
            [
              { text: "🔌 Network & Port Scan", callback_data: "launch_net_scan" },
              { text: "👤 Person / OSINT", callback_data: "target_person" }
            ],
            [
              { text: "🔙 Main Menu", callback_data: "main_menu" }
            ]
          ]
        }
      });
    } else if (data === "target_domain") {
      ctx.session.step = 'DOMAIN_INPUT';
      await safeEditMessageText(ctx, "🌐 <b>Target: Domain</b>\n\nPlease send me the target domain name (e.g. <code>example.com</code>):", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]] }
      });
    } else if (data === "target_person") {
      ctx.session.step = 'PERSON_INPUT';
      await safeEditMessageText(ctx, "🔍 <b>Target: Person / Lead</b>\n\nPlease send the person's name (e.g. <code>Cheth Ober</code>), username (<code>@che...</code>), or phone (<code>+1555...</code>):", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]] }
      });
    } else if (data === "target_company") {
      ctx.session.step = 'COMPANY_INPUT';
      await safeEditMessageText(ctx, "🏢 <b>Target: Company / Scope</b>\n\nPlease send me the company name or primary domain (e.g. <code>CHTH Corp</code> or <code>chth.xyz</code>):", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]] }
      });
    } else if (data === "launch_infogather") {
      ctx.session.step = 'INFOGATHER_INPUT';
      await safeEditMessageText(ctx, "🔍 <b>Launch Fast Info-Gathering</b>\n\nPlease send the domain to gather subdomains and probe live HTTP hosts (e.g. <code>target.com</code>):", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]] }
      });
    } else if (data === "launch_web_scan") {
      ctx.session.step = 'WEB_INPUT';
      await safeEditMessageText(ctx, "🌐 <b>Launch Web Crawl & Recon</b>\n\nPlease send the target URL or domain to crawl and discover endpoints (e.g. <code>target.com</code>):", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]] }
      });
    } else if (data === "launch_net_scan") {
      ctx.session.step = 'NET_INPUT';
      await safeEditMessageText(ctx, "🔌 <b>Launch Network & Port Scan</b>\n\nPlease send the target IP, domain, or CIDR range (e.g. <code>192.168.1.1</code> or <code>target.com</code>):", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]] }
      });
    }

    // ----------------------------------------------------
    // Targets & Companies Management
    // ----------------------------------------------------
    else if (data.startsWith("view_targets")) {
      const parts = data.split("_");
      const page = Number(parts[2] || 0);
      const offset = page * 8;

      const { results: companies } = await env.DB.prepare("SELECT * FROM companies ORDER BY created_at DESC LIMIT 8 OFFSET ?").bind(offset).all();
      const count = (await env.DB.prepare("SELECT count(*) as cnt FROM companies").first())?.cnt || 0;
      const totalPages = Math.ceil(count / 8) || 1;

      if (!companies.length && page === 0) {
        return await safeEditMessageText(ctx, "🎯 <b>Targets</b>\n\nNo target companies in database. Add one below:", {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "➕ Add Target Company", callback_data: "target_company" }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        });
      }

      const keyboard = [];
      for (const c of companies) {
        const dCount = (await env.DB.prepare("SELECT count(*) as cnt FROM domains WHERE company_id = ?").bind(c.id).first())?.cnt || 0;
        keyboard.push([{ text: `🏢 ${c.name} (${dCount} domains)`, callback_data: `view_company_${c.id}` }]);
      }

      keyboard.push([{ text: "➕ Add Target Company", callback_data: "target_company" }]);
      
      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Prev", callback_data: `view_targets_${page - 1}` });
      if (page + 1 < totalPages) navRow.push({ text: "Next ➡️", callback_data: `view_targets_${page + 1}` });
      if (navRow.length > 0) keyboard.push(navRow);
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

      await safeEditMessageText(ctx, `🎯 <b>Target Companies</b> (Page ${page + 1}/${totalPages})\n\nSelect a company to view details, manage domains, or trigger scans:`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_company_") && !data.includes("domains")) {
      const companyId = data.replace("view_company_", "");
      const comp = await env.DB.prepare("SELECT * FROM companies WHERE id = ?").bind(companyId).first();
      if (!comp) {
        return await safeEditMessageText(ctx, "❌ Company not found.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 Back to Targets", callback_data: "view_targets_0" }]] }
        });
      }

      const domCount = (await env.DB.prepare("SELECT count(*) as cnt FROM domains WHERE company_id = ?").bind(companyId).first())?.cnt || 0;
      const peopleCount = (await env.DB.prepare("SELECT count(*) as cnt FROM people WHERE company_id = ?").bind(companyId).first())?.cnt || 0;
      const findingsCount = (await env.DB.prepare("SELECT count(*) as cnt FROM findings WHERE company_id = ?").bind(companyId).first())?.cnt || 0;
      
      const compData = parseJson(comp.data);
      const phase = compData.phase || 'N/A';

      const text =
        `🏢 <b>Company: ${escapeHtml(comp.name)}</b>\n\n` +
        `• <b>ID:</b> <code>${comp.id}</code>\n` +
        `• <b>Slug:</b> <code>${comp.slug || 'N/A'}</code>\n` +
        `• <b>Recon Phase:</b> <code>${phase}</code>\n` +
        `• <b>Domains:</b> <b>${domCount}</b>\n` +
        `• <b>People:</b> <b>${peopleCount}</b>\n` +
        `• <b>Findings:</b> <b>${findingsCount}</b>\n` +
        `• <b>Created:</b> <code>${comp.created_at}</code>`;

      await safeEditMessageText(ctx, text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: `🌐 Domains (${domCount})`, callback_data: `view_company_domains_${companyId}_0` },
              { text: "➕ Add Domain", callback_data: `prep_add_dom_${companyId}` }
            ],
            [
              { text: "🚀 Full Recon Scan", callback_data: `scan_company_action_${companyId}` },
              { text: "🗑️ Delete Scope", callback_data: `confirm_del_comp_${companyId}` }
            ],
            [
              { text: "🔙 Back to Targets", callback_data: "view_targets_0" }
            ]
          ]
        }
      });
    } else if (data.startsWith("prep_add_dom_")) {
      const companyId = data.replace("prep_add_dom_", "");
      ctx.session.step = 'ADD_DOMAIN_INPUT';
      ctx.session.target_company_id = companyId;
      await safeEditMessageText(ctx, "➕ <b>Add Domain to Company</b>\n\nPlease send the host / domain name to add (e.g. <code>api.example.com</code>):", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🔙 Cancel", callback_data: `view_company_${companyId}` }]] }
      });
    } else if (data.startsWith("confirm_del_comp_")) {
      const companyId = data.replace("confirm_del_comp_", "");
      const comp = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(companyId).first();
      const compName = comp ? comp.name : "Company";
      await safeEditMessageText(ctx, `⚠️ <b>Delete Company: ${escapeHtml(compName)}</b>\n\nAre you sure you want to permanently delete this company and all associated domains, services, and findings?`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🗑️ Yes, Delete Everything", callback_data: `do_del_comp_${companyId}` }
            ],
            [
              { text: "🔙 Cancel", callback_data: `view_company_${companyId}` }
            ]
          ]
        }
      });
    } else if (data.startsWith("do_del_comp_")) {
      const companyId = data.replace("do_del_comp_", "");
      await env.DB.prepare("DELETE FROM companies WHERE id = ?").bind(companyId).run();
      await safeEditMessageText(ctx, "✅ Company and associated records successfully deleted.", {
        reply_markup: { inline_keyboard: [[{ text: "🔙 Back to Targets", callback_data: "view_targets_0" }]] }
      });
    } else if (data.startsWith("scan_company_action_")) {
      const companyId = data.replace("scan_company_action_", "");
      const comp = await env.DB.prepare("SELECT name, slug FROM companies WHERE id = ?").bind(companyId).first();
      if (!comp) return;
      const runner = ctx.session?.selected_runner || 'default';
      const jobId = await triggerScan(ctx, 'company', comp.name, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      await safeEditMessageText(ctx, `🚀 <b>Full Recon Scan Queued for ${escapeHtml(comp.name)}</b>\n\n• <b>Runner:</b> <code>${runner}</code>\n• <b>Job ID:</b> <code>${jobId}</code>`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
            [{ text: "🔙 Back to Company", callback_data: `view_company_${companyId}` }]
          ]
        }
      });
    }

    // ----------------------------------------------------
    // Domains Browsing & Operations
    // ----------------------------------------------------
    else if (data.startsWith("view_company_domains_")) {
      const parts = data.split("_");
      const companyId = parts[3];
      const page = Number(parts[4] || 0);
      const offset = page * 8;

      const comp = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(companyId).first();
      const compName = comp ? comp.name : "Company";

      const { results: domains } = await env.DB.prepare("SELECT * FROM domains WHERE company_id = ? ORDER BY created_at DESC LIMIT 8 OFFSET ?").bind(companyId, offset).all();
      const count = (await env.DB.prepare("SELECT count(*) as cnt FROM domains WHERE company_id = ?").bind(companyId).first())?.cnt || 0;
      const totalPages = Math.ceil(count / 8) || 1;

      if (!domains.length && page === 0) {
        return await safeEditMessageText(ctx, `🌐 <b>Domains for ${escapeHtml(compName)}</b>\n\nNo domains discovered yet.`, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "➕ Add Domain", callback_data: `prep_add_dom_${companyId}` }],
              [{ text: "🔙 Back to Company", callback_data: `view_company_${companyId}` }]
            ]
          }
        });
      }

      const keyboard = [];
      domains.forEach(d => {
        const domData = parseJson(d.data);
        const code = domData.status_code;
        let badge = "⚪";
        if (code >= 200 && code < 300) badge = "🟢";
        else if (code >= 300 && code < 400) badge = "🔵";
        else if (code >= 400 && code < 500) badge = "🔴";
        keyboard.push([{ text: `${badge} ${d.host}`, callback_data: `view_domain_${d.id}` }]);
      });

      keyboard.push([{ text: "➕ Add Domain", callback_data: `prep_add_dom_${companyId}` }]);

      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Prev", callback_data: `view_company_domains_${companyId}_${page - 1}` });
      if (page + 1 < totalPages) navRow.push({ text: "Next ➡️", callback_data: `view_company_domains_${companyId}_${page + 1}` });
      if (navRow.length > 0) keyboard.push(navRow);
      keyboard.push([{ text: "🔙 Back to Company", callback_data: `view_company_${companyId}` }]);

      await safeEditMessageText(ctx, `🌐 <b>Domains for ${escapeHtml(compName)}</b> (Page ${page + 1}/${totalPages})\n\nSelect a domain to inspect or scan:`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_domain_")) {
      const domainId = data.replace("view_domain_", "");
      const dom = await env.DB.prepare("SELECT * FROM domains WHERE id = ?").bind(domainId).first();
      if (!dom) {
        return await safeEditMessageText(ctx, "❌ Domain not found.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 Back to Targets", callback_data: "view_targets_0" }]] }
        });
      }

      const comp = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(dom.company_id).first();
      const domData = parseJson(dom.data);
      const title = domData.title || 'N/A';
      const webserver = domData.webserver || 'N/A';
      const status_code = domData.status_code || 'N/A';
      const tech = (domData.tech || []).join(', ') || 'None';

      const vulnCount = (await env.DB.prepare("SELECT count(*) as cnt FROM findings WHERE domain_id = ?").bind(domainId).first())?.cnt || 0;
      const secretsCount = (await env.DB.prepare("SELECT count(*) as cnt FROM secrets WHERE domain_id = ?").bind(domainId).first())?.cnt || 0;
      const servicesCount = (await env.DB.prepare("SELECT count(*) as cnt FROM network_services WHERE domain_id = ?").bind(domainId).first())?.cnt || 0;

      const text =
        `🌐 <b>Domain: ${escapeHtml(dom.host)}</b>\n\n` +
        `• <b>Company:</b> ${comp ? escapeHtml(comp.name) : 'N/A'}\n` +
        `• <b>Canonical URL:</b> <code>${escapeHtml(dom.canonical_url || `http://${dom.host}`)}</code>\n` +
        `• <b>Status Code:</b> <code>${status_code}</code>\n` +
        `• <b>Title:</b> ${escapeHtml(title)}\n` +
        `• <b>Web Server:</b> <code>${escapeHtml(webserver)}</code>\n` +
        `• <b>Technologies:</b> <code>${escapeHtml(tech)}</code>\n\n` +
        `🛡️ <b>Findings:</b> ${vulnCount} | 🔑 <b>Secrets:</b> ${secretsCount} | 🔌 <b>Ports:</b> ${servicesCount}`;

      await safeEditMessageText(ctx, text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🚀 Recon", callback_data: `scan_dom_recon_${domainId}` },
              { text: "🔍 Info-Gather", callback_data: `scan_dom_info_${domainId}` }
            ],
            [
              { text: "🌐 Web Crawl", callback_data: `scan_dom_web_${domainId}` },
              { text: "🔌 Port Scan", callback_data: `scan_dom_net_${domainId}` }
            ],
            [
              { text: `🛡️ Findings (${vulnCount})`, callback_data: `view_dom_vulns_${domainId}_0` },
              { text: `🔑 Secrets (${secretsCount})`, callback_data: `view_dom_secrets_${domainId}_0` }
            ],
            [
              { text: "🗑️ Delete Domain", callback_data: `confirm_del_dom_${domainId}` },
              { text: "🔙 Back", callback_data: `view_company_domains_${dom.company_id}_0` }
            ]
          ]
        }
      });
    } else if (data.startsWith("confirm_del_dom_")) {
      const domainId = data.replace("confirm_del_dom_", "");
      const dom = await env.DB.prepare("SELECT host, company_id FROM domains WHERE id = ?").bind(domainId).first();
      if (!dom) return;
      await safeEditMessageText(ctx, `⚠️ <b>Delete Domain: ${escapeHtml(dom.host)}</b>\n\nAre you sure you want to remove this domain and its associated endpoints/findings?`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "🗑️ Yes, Delete", callback_data: `do_del_dom_${domainId}` }],
            [{ text: "🔙 Cancel", callback_data: `view_domain_${domainId}` }]
          ]
        }
      });
    } else if (data.startsWith("do_del_dom_")) {
      const domainId = data.replace("do_del_dom_", "");
      const dom = await env.DB.prepare("SELECT company_id FROM domains WHERE id = ?").bind(domainId).first();
      await env.DB.prepare("DELETE FROM domains WHERE id = ?").bind(domainId).run();
      const returnCompId = dom ? dom.company_id : null;
      await safeEditMessageText(ctx, "✅ Domain successfully deleted.", {
        reply_markup: {
          inline_keyboard: [
            returnCompId
              ? [{ text: "🔙 Back to Company Domains", callback_data: `view_company_domains_${returnCompId}_0` }]
              : [{ text: "🔙 Back to Targets", callback_data: "view_targets_0" }]
          ]
        }
      });
    } else if (data.startsWith("scan_dom_")) {
      const parts = data.split("_");
      const scanType = parts[2]; // recon, info, web, net
      const domainId = parts[3];
      const dom = await env.DB.prepare("SELECT host FROM domains WHERE id = ?").bind(domainId).first();
      if (!dom) return;
      const runner = ctx.session?.selected_runner || 'default';

      let typeKey = 'domain';
      if (scanType === 'info') typeKey = 'infogather';
      else if (scanType === 'web') typeKey = 'web';
      else if (scanType === 'net') typeKey = 'network';

      const jobId = await triggerScan(ctx, typeKey, dom.host, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      await safeEditMessageText(ctx, `🚀 <b>Scan Queued for ${escapeHtml(dom.host)}</b>\n\n• <b>Type:</b> <code>${scanType.toUpperCase()}</code>\n• <b>Runner:</b> <code>${runner}</code>\n• <b>Job ID:</b> <code>${jobId}</code>`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
            [{ text: "🔙 Back to Domain", callback_data: `view_domain_${domainId}` }]
          ]
        }
      });
    }

    // ----------------------------------------------------
    // Contacts (People) Management
    // ----------------------------------------------------
    else if (data.startsWith("view_contacts")) {
      const parts = data.split("_");
      const page = Number(parts[2] || 0);
      const offset = page * 8;

      const { results: people } = await env.DB.prepare("SELECT * FROM people ORDER BY created_at DESC LIMIT 8 OFFSET ?").bind(offset).all();
      const count = (await env.DB.prepare("SELECT count(*) as cnt FROM people").first())?.cnt || 0;
      const totalPages = Math.ceil(count / 8) || 1;

      if (!people.length && page === 0) {
        return await safeEditMessageText(ctx, "👥 <b>Contacts & People</b>\n\nNo contacts found in database. Add one below:", {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "➕ Add New Person", callback_data: "target_person" }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        });
      }

      const keyboard = [];
      for (const p of people) {
        const name = `${p.given_name || ''} ${p.family_name || ''}`.trim() || 'Unnamed';
        const badge = osintBadge(p.data);
        keyboard.push([{ text: `👤 ${name}${badge ? ` ${badge}` : ''}`, callback_data: `view_contact_${p.id}` }]);
      }

      keyboard.push([{ text: "➕ Add New Person", callback_data: "target_person" }]);

      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Prev", callback_data: `view_contacts_${page - 1}` });
      if (page + 1 < totalPages) navRow.push({ text: "Next ➡️", callback_data: `view_contacts_${page + 1}` });
      if (navRow.length > 0) keyboard.push(navRow);
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

      await safeEditMessageText(ctx, `👥 <b>Contacts & People</b> (Page ${page + 1}/${totalPages})\n\nSelect a contact to inspect details, launch OSINT search, or remove:`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_contact_")) {
      const contactId = data.replace("view_contact_", "");
      const person = await env.DB.prepare("SELECT * FROM people WHERE id = ?").bind(contactId).first();
      if (!person) {
        return await safeEditMessageText(ctx, "❌ Contact not found.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 Back to Contacts", callback_data: "view_contacts_0" }]] }
        });
      }
      
      const emails = parseJson(person.emails).join(', ') || "None";
      const phones = parseJson(person.phones).join(', ') || "None";
      const company = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(person.company_id).first();
      const name = `${person.given_name || ''} ${person.family_name || ''}`.trim() || 'Unnamed';
      const username = parseJson(person.data).username || "No Username";

      const text =
        `👤 <b>Contact: ${escapeHtml(name)}</b>\n\n` +
        `• <b>ID:</b> <code>${person.id}</code>\n` +
        `• <b>Username:</b> <code>${escapeHtml(username)}</code>\n` +
        `• <b>Company:</b> ${company ? escapeHtml(company.name) : 'N/A'}\n` +
        `• <b>Emails:</b> <code>${escapeHtml(emails)}</code>\n` +
        `• <b>Phones:</b> <code>${escapeHtml(phones)}</code>\n` +
        `• <b>Notes:</b> ${escapeHtml(person.notes || 'None')}\n` +
        `• <b>Created At:</b> <code>${person.created_at}</code>` +
        formatOsintSummary(person.data);

      await safeEditMessageText(ctx, text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🚀 OSINT Scan Person", callback_data: `scan_person_action_${person.id}` },
              { text: "🗑️ Delete Contact", callback_data: `confirm_del_person_${person.id}` }
            ],
            [
              { text: "🔙 Back to Contacts", callback_data: "view_contacts_0" }
            ]
          ]
        }
      });
    } else if (data.startsWith("confirm_del_person_")) {
      const contactId = data.replace("confirm_del_person_", "");
      const person = await env.DB.prepare("SELECT given_name, family_name FROM people WHERE id = ?").bind(contactId).first();
      const name = person ? `${person.given_name} ${person.family_name || ''}`.trim() : 'Contact';
      await safeEditMessageText(ctx, `⚠️ <b>Delete Contact: ${escapeHtml(name)}</b>\n\nAre you sure you want to remove this contact from the database?`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "🗑️ Yes, Delete", callback_data: `do_del_person_${contactId}` }],
            [{ text: "🔙 Cancel", callback_data: `view_contact_${contactId}` }]
          ]
        }
      });
    } else if (data.startsWith("do_del_person_")) {
      const contactId = data.replace("do_del_person_", "");
      await env.DB.prepare("DELETE FROM people WHERE id = ?").bind(contactId).run();
      await safeEditMessageText(ctx, "✅ Contact successfully deleted.", {
        reply_markup: { inline_keyboard: [[{ text: "🔙 Back to Contacts", callback_data: "view_contacts_0" }]] }
      });
    } else if (data.startsWith("scan_person_action_")) {
      const contactId = data.replace("scan_person_action_", "");
      const person = await env.DB.prepare("SELECT given_name, family_name FROM people WHERE id = ?").bind(contactId).first();
      if (!person) return;
      const fullName = `${person.given_name} ${person.family_name || ''}`.trim();
      const runner = ctx.session?.selected_runner || 'default';
      const jobId = await triggerScan(ctx, 'person', fullName, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      await safeEditMessageText(ctx, `🚀 <b>OSINT Scan Queued for ${escapeHtml(fullName)}</b>\n\n• <b>Runner:</b> <code>${runner}</code>\n• <b>Job ID:</b> <code>${jobId}</code>`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
            [{ text: "🔙 Back to Contact", callback_data: `view_contact_${contactId}` }]
          ]
        }
      });
    }

    // ----------------------------------------------------
    // Scan Queue & Job Control
    // ----------------------------------------------------
    else if (data === "view_new_domains" || data === "menu_queue") {
      const { results: jobs } = await env.DB.prepare(
        "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT 10"
      ).all();
      
      if (!jobs.length) {
        return await safeEditMessageText(
          ctx,
          "📜 <b>Scan Queue</b>\n\nNo scan jobs currently in the queue.", 
          {
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "🚀 Launch Scan", callback_data: "menu_scan" }],
                [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
              ]
            }
          }
        );
      }
      
      const keyboard = [];
      jobs.forEach(job => {
        let badge = "⏳";
        if (job.status === 'running') badge = "🔄";
        else if (job.status === 'completed') badge = "✅";
        else if (job.status === 'failed') badge = "🛑";
        keyboard.push([{ text: `${badge} ${job.domain} (${job.runner || 'default'})`, callback_data: `manage_job:${job.id}` }]);
      });

      keyboard.push([
        { text: "🔄 Refresh", callback_data: "view_new_domains" },
        { text: "🧹 Clean Finished", callback_data: "action_clean_queue" }
      ]);
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

      await safeEditMessageText(
        ctx,
        `📜 <b>Scan Jobs Queue (${jobs.length})</b>\n\nClick any job to view live logs, stop execution, or re-run:`,
        {
          parse_mode: "HTML",
          reply_markup: { inline_keyboard: keyboard }
        }
      );
    } else if (data.startsWith("manage_job:")) {
      const jobId = data.split(":")[1];
      const job = await env.DB.prepare("SELECT * FROM scan_jobs WHERE id = ?").bind(jobId).first();
      if (!job) {
        return await safeEditMessageText(ctx, "❌ Job not found.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 Back to Queue", callback_data: "view_new_domains" }]] }
        });
      }

      let statusBadge = "⏳ Pending";
      if (job.status === 'running') statusBadge = "🔄 Running";
      else if (job.status === 'completed') statusBadge = "✅ Completed";
      else if (job.status === 'failed') statusBadge = "🛑 Stopped / Failed";

      const rawStdout = job.stdout || '';
      const stdoutSnippet = rawStdout.length > 1200 ? '...' + rawStdout.substring(rawStdout.length - 1200) : rawStdout || 'No output recorded yet.';

      const text =
        `📜 <b>Scan Job Details:</b>\n\n` +
        `• <b>Target:</b> <code>${escapeHtml(job.domain)}</code>\n` +
        `• <b>Status:</b> ${statusBadge}\n` +
        `• <b>Runner:</b> <code>${escapeHtml(job.runner || 'default')}</code>\n` +
        `• <b>Command:</b> <code>${escapeHtml(job.command)}</code>\n` +
        `• <b>Created:</b> <code>${job.created_at}</code>\n` +
        `• <b>Updated:</b> <code>${job.updated_at || job.created_at}</code>\n\n` +
        `<b>Live Output Logs:</b>\n<pre>${escapeHtml(stdoutSnippet)}</pre>`;

      const actionsRow = [];
      if (job.status === 'running' || job.status === 'pending') {
        actionsRow.push({ text: "🛑 Stop Scan", callback_data: `job_stop:${job.id}` });
      } else {
        actionsRow.push({ text: "🔁 Re-run Scan", callback_data: `job_restart:${job.id}` });
      }
      actionsRow.push({ text: "🗑️ Delete Job", callback_data: `job_delete:${job.id}` });

      await safeEditMessageText(ctx, text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "🔄 Refresh Logs", callback_data: `manage_job:${job.id}` }],
            actionsRow,
            [{ text: "🔙 Back to Queue", callback_data: "view_new_domains" }]
          ]
        }
      });
    } else if (data.startsWith("job_stop:")) {
      const jobId = data.split(":")[1];
      await env.DB.prepare("UPDATE scan_jobs SET status = 'failed', stdout = stdout || '\n[CANCELLED BY USER]', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(jobId).run();
      await ctx.answerCallbackQuery({ text: "🛑 Scan stopped.", show_alert: false });
      ctx.callbackQuery.data = `manage_job:${jobId}`;
      return bot.handleUpdate(ctx.update);
    } else if (data.startsWith("job_restart:")) {
      const jobId = data.split(":")[1];
      await env.DB.prepare("UPDATE scan_jobs SET status = 'pending', stdout = '', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(jobId).run();
      await ctx.answerCallbackQuery({ text: "🔁 Scan job re-queued.", show_alert: false });
      ctx.callbackQuery.data = `manage_job:${jobId}`;
      return bot.handleUpdate(ctx.update);
    } else if (data.startsWith("job_delete:")) {
      const jobId = data.split(":")[1];
      await env.DB.prepare("DELETE FROM scan_jobs WHERE id = ?").bind(jobId).run();
      await ctx.answerCallbackQuery({ text: "🗑️ Job deleted.", show_alert: false });
      ctx.callbackQuery.data = "view_new_domains";
      return bot.handleUpdate(ctx.update);
    } else if (data === "action_clean_queue") {
      await env.DB.prepare("DELETE FROM scan_jobs WHERE status IN ('completed', 'failed')").run();
      await ctx.answerCallbackQuery({ text: "🧹 Cleaned up finished scan jobs.", show_alert: true });
      ctx.callbackQuery.data = "view_new_domains";
      return bot.handleUpdate(ctx.update);
    }

    // ----------------------------------------------------
    // Findings & Vulnerability Triage
    // ----------------------------------------------------
    else if (data === "menu_findings" || data.startsWith("menu_findings_")) {
      const parts = data.split("_");
      const severityFilter = parts[2] || "all";
      const page = Number(parts[3] || 0);
      const offset = page * 6;

      let query = `
        SELECT f.*, d.host FROM findings f
        JOIN domains d ON f.domain_id = d.id
        WHERE 1=1
      `;
      const binds = [];
      if (severityFilter !== "all") {
        query += " AND lower(f.severity) = lower(?)";
        binds.push(severityFilter);
      }
      query += " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.created_at DESC LIMIT 6 OFFSET ?";
      binds.push(offset);

      const { results: findings } = await env.DB.prepare(query).bind(...binds).all();

      let countQuery = "SELECT count(*) as cnt FROM findings";
      let countBinds = [];
      if (severityFilter !== "all") {
        countQuery += " WHERE lower(severity) = lower(?)";
        countBinds.push(severityFilter);
      }
      const count = (await env.DB.prepare(countQuery).bind(...countBinds).first())?.cnt || 0;
      const totalPages = Math.ceil(count / 6) || 1;

      const keyboard = [
        [
          { text: "🔴 Crit", callback_data: "menu_findings_critical_0" },
          { text: "🟠 High", callback_data: "menu_findings_high_0" },
          { text: "🟡 Med", callback_data: "menu_findings_medium_0" },
          { text: "🔵 Low", callback_data: "menu_findings_low_0" },
          { text: "📋 All", callback_data: "menu_findings_all_0" }
        ]
      ];

      const emojiMap = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
      findings.forEach(f => {
        const em = emojiMap[f.severity.toLowerCase()] || '⚪';
        let stBadge = f.status === 'resolved' ? '✅' : (f.status === 'false_positive' ? '🚫' : '');
        keyboard.push([{
          text: `${em} ${f.title.substring(0, 32)} ${stBadge}`,
          callback_data: `view_finding:${f.id}:${severityFilter}:${page}`
        }]);
      });

      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Prev", callback_data: `menu_findings_${severityFilter}_${page - 1}` });
      if (page + 1 < totalPages) navRow.push({ text: "Next ➡️", callback_data: `menu_findings_${severityFilter}_${page + 1}` });
      if (navRow.length > 0) keyboard.push(navRow);

      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

      const filterTitle = severityFilter.toUpperCase();
      await safeEditMessageText(ctx, `🛡️ <b>Vulnerabilities Triage [${filterTitle}]</b> (${count} findings, Page ${page + 1}/${totalPages})\n\nSelect a vulnerability finding to inspect evidence or update triage status:`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_finding:")) {
      const parts = data.split(":");
      const findingId = parts[1];
      const lastSev = parts[2] || "all";
      const lastPage = parts[3] || "0";

      const finding = await env.DB.prepare(`
        SELECT f.*, d.host FROM findings f
        JOIN domains d ON f.domain_id = d.id
        WHERE f.id = ?
      `).bind(findingId).first();

      if (!finding) {
        return await safeEditMessageText(ctx, "❌ Finding not found.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 Back", callback_data: `menu_findings_${lastSev}_${lastPage}` }]] }
        });
      }

      const emojiMap = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
      const em = emojiMap[finding.severity.toLowerCase()] || '⚪';

      let statusBadge = "🟡 Open";
      if (finding.status === 'resolved') statusBadge = "✅ Resolved";
      else if (finding.status === 'false_positive') statusBadge = "🚫 False Positive";

      const poc = finding.poc || finding.evidence || 'No PoC / Evidence provided.';

      const text =
        `🛡️ <b>Finding: ${escapeHtml(finding.title)}</b>\n\n` +
        `• <b>Severity:</b> ${em} <code>${escapeHtml(finding.severity.toUpperCase())}</code>\n` +
        `• <b>Status:</b> <b>${statusBadge}</b>\n` +
        `• <b>Type:</b> <code>${escapeHtml(finding.vuln_type)}</code>\n` +
        `• <b>Tool:</b> <code>${escapeHtml(finding.tool)}</code>\n` +
        `• <b>Target URL / Host:</b> <code>${escapeHtml(finding.url || finding.host)}</code>\n` +
        (finding.cve ? `• <b>CVE:</b> <code>${escapeHtml(finding.cve)}</code>\n` : '') +
        `• <b>Created:</b> <code>${finding.created_at}</code>\n\n` +
        `<b>Proof of Concept / Evidence:</b>\n<pre>${escapeHtml(poc.substring(0, 800))}</pre>`;

      await safeEditMessageText(ctx, text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "✅ Resolve", callback_data: `set_finding_st:${finding.id}:resolved:${lastSev}:${lastPage}` },
              { text: "🚫 False Positive", callback_data: `set_finding_st:${finding.id}:false_positive:${lastSev}:${lastPage}` },
              { text: "🔄 Reopen", callback_data: `set_finding_st:${finding.id}:open:${lastSev}:${lastPage}` }
            ],
            [
              { text: "🗑️ Delete Finding", callback_data: `del_finding:${finding.id}:${lastSev}:${lastPage}` },
              { text: "🔙 Back to Findings", callback_data: `menu_findings_${lastSev}_${lastPage}` }
            ]
          ]
        }
      });
    } else if (data.startsWith("set_finding_st:")) {
      const parts = data.split(":");
      const findingId = parts[1];
      const newStatus = parts[2];
      const lastSev = parts[3] || "all";
      const lastPage = parts[4] || "0";

      await env.DB.prepare("UPDATE findings SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(newStatus, findingId).run();
      await ctx.answerCallbackQuery({ text: `Status updated to ${newStatus}`, show_alert: false });
      ctx.callbackQuery.data = `view_finding:${findingId}:${lastSev}:${lastPage}`;
      return bot.handleUpdate(ctx.update);
    } else if (data.startsWith("del_finding:")) {
      const parts = data.split(":");
      const findingId = parts[1];
      const lastSev = parts[2] || "all";
      const lastPage = parts[3] || "0";

      await env.DB.prepare("DELETE FROM findings WHERE id = ?").bind(findingId).run();
      await ctx.answerCallbackQuery({ text: "🗑️ Finding deleted.", show_alert: false });
      ctx.callbackQuery.data = `menu_findings_${lastSev}_${lastPage}`;
      return bot.handleUpdate(ctx.update);
    }

    // ----------------------------------------------------
    // Secrets Browser
    // ----------------------------------------------------
    else if (data.startsWith("menu_secrets_")) {
      const page = Number(data.replace("menu_secrets_", "") || 0);
      const offset = page * 6;

      const { results: secrets } = await env.DB.prepare(`
        SELECT s.*, d.host FROM secrets s
        JOIN domains d ON s.domain_id = d.id
        ORDER BY s.created_at DESC LIMIT 6 OFFSET ?
      `).bind(offset).all();

      const count = (await env.DB.prepare("SELECT count(*) as cnt FROM secrets").first())?.cnt || 0;
      const totalPages = Math.ceil(count / 6) || 1;

      if (!secrets.length && page === 0) {
        return await safeEditMessageText(ctx, "🔑 <b>Discovered Secrets</b>\n\nNo leaked secrets found in database.", {
          parse_mode: "HTML",
          reply_markup: { inline_keyboard: [[{ text: "🔙 Main Menu", callback_data: "main_menu" }]] }
        });
      }

      const keyboard = [];
      secrets.forEach(s => {
        keyboard.push([{ text: `🔑 ${s.rule_name} (${s.secret_type})`, callback_data: `view_secret:${s.id}:${page}` }]);
      });

      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Prev", callback_data: `menu_secrets_${page - 1}` });
      if (page + 1 < totalPages) navRow.push({ text: "Next ➡️", callback_data: `menu_secrets_${page + 1}` });
      if (navRow.length > 0) keyboard.push(navRow);
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

      await safeEditMessageText(ctx, `🔑 <b>Discovered Secrets (${count})</b> (Page ${page + 1}/${totalPages})\n\nSelect a secret to view match snippet and source file:`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_secret:")) {
      const parts = data.split(":");
      const secretId = parts[1];
      const page = parts[2] || "0";

      const secret = await env.DB.prepare(`
        SELECT s.*, d.host FROM secrets s
        JOIN domains d ON s.domain_id = d.id
        WHERE s.id = ?
      `).bind(secretId).first();

      if (!secret) {
        return await safeEditMessageText(ctx, "❌ Secret not found.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 Back", callback_data: `menu_secrets_${page}` }]] }
        });
      }

      const text =
        `🔑 <b>Secret: ${escapeHtml(secret.rule_name)}</b>\n\n` +
        `• <b>Type:</b> <code>${escapeHtml(secret.secret_type)}</code>\n` +
        `• <b>Severity:</b> <code>${escapeHtml(secret.severity.toUpperCase())}</code>\n` +
        `• <b>Host:</b> <code>${escapeHtml(secret.host)}</code>\n` +
        `• <b>File / Endpoint:</b> <code>${escapeHtml(secret.file_url || secret.host)}</code>\n` +
        `• <b>Discovered:</b> <code>${secret.created_at}</code>\n\n` +
        `<b>Match Snippet:</b>\n<pre>${escapeHtml(secret.match_snippet)}</pre>`;

      await safeEditMessageText(ctx, text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🗑️ Delete Secret", callback_data: `del_secret:${secret.id}:${page}` },
              { text: "🔙 Back to Secrets", callback_data: `menu_secrets_${page}` }
            ]
          ]
        }
      });
    } else if (data.startsWith("del_secret:")) {
      const parts = data.split(":");
      const secretId = parts[1];
      const page = parts[2] || "0";

      await env.DB.prepare("DELETE FROM secrets WHERE id = ?").bind(secretId).run();
      await ctx.answerCallbackQuery({ text: "🗑️ Secret deleted.", show_alert: false });
      ctx.callbackQuery.data = `menu_secrets_${page}`;
      return bot.handleUpdate(ctx.update);
    }

    // ----------------------------------------------------
    // Services & Open Ports Browser
    // ----------------------------------------------------
    else if (data.startsWith("menu_services_")) {
      const page = Number(data.replace("menu_services_", "") || 0);
      const offset = page * 8;

      const { results: services } = await env.DB.prepare(`
        SELECT ns.*, d.host FROM network_services ns
        JOIN domains d ON ns.domain_id = d.id
        ORDER BY ns.port ASC LIMIT 8 OFFSET ?
      `).bind(offset).all();

      const count = (await env.DB.prepare("SELECT count(*) as cnt FROM network_services").first())?.cnt || 0;
      const totalPages = Math.ceil(count / 8) || 1;

      if (!services.length && page === 0) {
        return await safeEditMessageText(ctx, "🔌 <b>Network Services & Open Ports</b>\n\nNo open ports found in database.", {
          parse_mode: "HTML",
          reply_markup: { inline_keyboard: [[{ text: "🔙 Main Menu", callback_data: "main_menu" }]] }
        });
      }

      const keyboard = [];
      services.forEach(s => {
        keyboard.push([{
          text: `🔌 ${s.ip}:${s.port} (${s.service || 'unknown'})`,
          callback_data: `view_service:${s.id}:${page}`
        }]);
      });

      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Prev", callback_data: `menu_services_${page - 1}` });
      if (page + 1 < totalPages) navRow.push({ text: "Next ➡️", callback_data: `menu_services_${page + 1}` });
      if (navRow.length > 0) keyboard.push(navRow);
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

      await safeEditMessageText(ctx, `🔌 <b>Network Services (${count})</b> (Page ${page + 1}/${totalPages})\n\nSelect a service to inspect port details:`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_service:")) {
      const parts = data.split(":");
      const serviceId = parts[1];
      const page = parts[2] || "0";

      const service = await env.DB.prepare(`
        SELECT ns.*, d.host FROM network_services ns
        JOIN domains d ON ns.domain_id = d.id
        WHERE ns.id = ?
      `).bind(serviceId).first();

      if (!service) {
        return await safeEditMessageText(ctx, "❌ Service not found.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 Back", callback_data: `menu_services_${page}` }]] }
        });
      }

      const text =
        `🔌 <b>Service: ${escapeHtml(service.ip)}:${service.port}</b>\n\n` +
        `• <b>Protocol:</b> <code>${escapeHtml(service.protocol || 'tcp')}</code>\n` +
        `• <b>Service Name:</b> <code>${escapeHtml(service.service || 'unknown')}</code>\n` +
        `• <b>Product:</b> <code>${escapeHtml(service.product || 'N/A')}</code>\n` +
        `• <b>Version:</b> <code>${escapeHtml(service.version || 'N/A')}</code>\n` +
        `• <b>Host:</b> <code>${escapeHtml(service.host)}</code>\n` +
        `• <b>Discovered:</b> <code>${service.created_at}</code>\n\n` +
        (service.banner ? `<b>Banner:</b>\n<pre>${escapeHtml(service.banner.substring(0, 500))}</pre>` : '');

      await safeEditMessageText(ctx, text, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "🗑️ Delete Service", callback_data: `del_service:${service.id}:${page}` },
              { text: "🔙 Back to Services", callback_data: `menu_services_${page}` }
            ]
          ]
        }
      });
    } else if (data.startsWith("del_service:")) {
      const parts = data.split(":");
      const serviceId = parts[1];
      const page = parts[2] || "0";

      await env.DB.prepare("DELETE FROM network_services WHERE id = ?").bind(serviceId).run();
      await ctx.answerCallbackQuery({ text: "🗑️ Service deleted.", show_alert: false });
      ctx.callbackQuery.data = `menu_services_${page}`;
      return bot.handleUpdate(ctx.update);
    }

    // ----------------------------------------------------
    // Runners Management
    // ----------------------------------------------------
    else if (data === "change_runner") {
      ctx.session.step = 'RUNNER_SELECTION';
      const runnerMarkup = await createRunnerKeyboard();
      await safeEditMessageText(
        ctx,
        "⚙️ <b>Runners Management</b>\n\n" +
        "Select a runner to set it as active or manage its settings (🟢 indicates online in the last 60s, 🔴 indicates offline):",
        {
          parse_mode: "HTML",
          reply_markup: runnerMarkup
        }
      );
    } else if (data.startsWith("select_runner:")) {
      const runner = data.split(":").pop();
      ctx.session.selected_runner = runner;
      ctx.session.step = 'MAIN_MENU';
      await ctx.answerCallbackQuery({ text: `Active runner set to ${runner}`, show_alert: false });
      const menuMarkup = await createMainMenu(ctx, env);
      await safeEditMessageText(ctx, `✅ <b>Active runner updated to:</b> <code>${escapeHtml(runner)}</code>\n\nSelect an option below:`, {
        parse_mode: "HTML",
        reply_markup: menuMarkup
      });
    } else if (data.startsWith("manage_runner:")) {
      const runnerName = data.split(":").pop();
      try {
        const runner = await env.DB.prepare(
          "SELECT * FROM runners WHERE name = ?"
        ).bind(runnerName).first();

        if (!runner) {
          return await ctx.answerCallbackQuery({
            text: "Runner not found.",
            show_alert: true
          });
        }

        const cutoff = Math.floor(Date.now() / 1000) - 60;
        const isActive = runner.last_seen >= cutoff;
        const statusStr = isActive ? "🟢 <b>Active</b>" : "🔴 <b>Inactive</b>";
        const lastSeenStr = new Date(runner.last_seen * 1000).toISOString().replace('T', ' ').substring(0, 19) + " UTC";
        const flag = getFlagEmoji(runner.country);

        const detailsText = 
          `⚙️ <b>Manage Runner:</b> <code>${escapeHtml(runner.name)}</code>\n\n` +
          `• <b>Status:</b> ${statusStr}\n` +
          `• <b>IP Address:</b> <code>${escapeHtml(runner.ip || 'N/A')}</code>\n` +
          `• <b>Country:</b> ${flag} ${escapeHtml(runner.country || 'N/A')}\n` +
          `• <b>Last Seen:</b> <code>${lastSeenStr}</code>\n\n` +
          `Select an option below:`;

        await safeEditMessageText(ctx, detailsText, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "✅ Select as Active", callback_data: `select_runner:${runner.name}` }],
              [
                { text: "✏️ Rename", callback_data: `prep_rename:${runner.name}` },
                { text: "❌ Remove / Delete", callback_data: `remove_runner:${runner.name}` }
              ],
              [{ text: "🔙 Back to Runners", callback_data: "change_runner" }]
            ]
          }
        });
      } catch (err) {
        console.error("D1 error in manage_runner:", err.message);
      }
    } else if (data.startsWith("prep_rename:")) {
      const runnerName = data.split(":").pop();
      ctx.session.step = 'RENAME_RUNNER';
      ctx.session.target_runner = runnerName;
      await safeEditMessageText(ctx, `✏️ <b>Rename Runner:</b> <code>${escapeHtml(runnerName)}</code>\n\nPlease send the new name for this runner:`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🔙 Cancel", callback_data: `manage_runner:${runnerName}` }]]
        }
      });
    } else if (data.startsWith("remove_runner:")) {
      const runnerName = data.split(":").pop();
      try {
        await env.DB.prepare("DELETE FROM runners WHERE name = ?").bind(runnerName).run();
        if (ctx.session.selected_runner === runnerName) {
          ctx.session.selected_runner = 'default';
        }

        await safeEditMessageText(ctx, `❌ Runner <code>${escapeHtml(runnerName)}</code> has been removed from the database.`, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Go to Runners", callback_data: "change_runner" }]]
          }
        });
      } catch (err) {
        console.error("D1 error in remove_runner:", err.message);
      }
    } else if (data === "confirm_reset_db") {
      if (!await requireRole(ctx, 'superadmin', 'db.reset')) return;
      await safeEditMessageText(
        ctx,
        `⚠️ <b>DANGER: Reset Cloudflare Database</b>\n\n` +
        `Are you sure you want to permanently delete <b>ALL</b> data in Cloudflare DB?\n\n` +
        `This will delete:\n` +
        `• 🏢 Companies & Scopes\n` +
        `• 🌐 Domains & Subdomains\n` +
        `• 👥 Contacts & People\n` +
        `• 🛡️ Vulnerabilities & Findings\n` +
        `• 🔑 Secrets & Leaks\n` +
        `• 🔌 Open Services & Ports\n` +
        `• 🔗 Discovered Endpoints\n` +
        `• 📜 Scan Jobs Queue & Logs\n` +
        `• 🖥️ Registered Runners\n` +
        `• 👤 Users & Sessions\n\n` +
        `<b>This action is permanent and cannot be undone!</b>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [
                { text: "🔴 Yes, Wipe & Reset All Data", callback_data: "do_reset_db" }
              ],
              [
                { text: "🔙 Cancel", callback_data: "main_menu" }
              ]
            ]
          }
        }
      );
    } else if (data === "do_reset_db") {
      if (!await requireRole(ctx, 'superadmin', 'db.reset')) return;
      try {
        // Note: audit_log is intentionally NOT wiped — the audit trail must
        // survive a database reset. team_members is cleared with its users.
        const tables = [
          "findings",
          "secrets",
          "network_services",
          "endpoints",
          "people",
          "domains",
          "companies",
          "scan_jobs",
          "runners",
          "sessions",
          "team_members",
          "users"
        ];
        const statements = tables.map(t => env.DB.prepare(`DELETE FROM ${t}`));
        await env.DB.batch(statements);
        await auditLog(env, {
          actor_user_id: ctx.actor?.userId, actor_number_id: ctx.from?.id || 0,
          actor_label: ctx.actor?.username, source: 'telegram', action: 'db.reset',
          target_type: 'db', target: 'all', detail: { tables },
        });

        ctx.session = {
          selected_runner: 'default',
          step: 'MAIN_MENU',
          user_registered: false
        };
        await registerUser(ctx);

        await safeEditMessageText(ctx, "✅ <b>Cloudflare Database Cleared!</b>\n\nAll targets, scan jobs, findings, secrets, services, runners, and sessions have been deleted successfully.", {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        });
      } catch (err) {
        console.error("D1 reset error:", err.message);
        await safeEditMessageText(ctx, `❌ Failed to reset database: ${escapeHtml(err.message)}`, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Main Menu", callback_data: "main_menu" }]]
          }
        });
      }
    }
  });

  // ----------------------------------------------------
  // Bot Text Messages (Input State Router)
  // ----------------------------------------------------
  bot.on("message:text", async (ctx) => {
    await registerUser(ctx);
    const text = ctx.message.text.trim();
    const step = ctx.session.step;

    if (!ctx.session.selected_runner) {
      const runnersList = (env.RUNNERS || "VPS-1,VPS-2").split(",").map(r => r.trim());
      ctx.session.selected_runner = runnersList[0] || 'default';
    }

    const runner = ctx.session.selected_runner;

    if (step === 'DOMAIN_INPUT') {
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(text);
      if (!isDomain) {
        return await ctx.reply("❌ Invalid domain format. Try again or type /menu to reset.");
      }
      const jobId = await triggerScan(ctx, 'domain', text, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      ctx.session.step = 'MAIN_MENU';
      await ctx.reply(
        `🚀 <b>Full Recon Scan Queued!</b>\n\n` +
        `• <b>Target:</b> <code>${escapeHtml(text)}</code>\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Job ID:</b> <code>${jobId}</code>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    } 
    else if (step === 'PERSON_INPUT') {
      const jobId = await triggerScan(ctx, 'person', text, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      ctx.session.step = 'MAIN_MENU';
      await ctx.reply(
        `🔍 <b>Person OSINT Scan Queued!</b>\n\n` +
        `• <b>Target:</b> <code>${escapeHtml(text)}</code>\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Job ID:</b> <code>${jobId}</code>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    } 
    else if (step === 'COMPANY_INPUT') {
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(text);
      const targetType = isDomain ? 'domain' : 'company';
      const jobId = await triggerScan(ctx, targetType, text, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      ctx.session.step = 'MAIN_MENU';
      
      await ctx.reply(
        `🏢 <b>Company Recon Scan Queued!</b>\n\n` +
        `• <b>Target:</b> <code>${escapeHtml(text)}</code>\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Job ID:</b> <code>${jobId}</code>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    }
    else if (step === 'INFOGATHER_INPUT') {
      const jobId = await triggerScan(ctx, 'infogather', text, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      ctx.session.step = 'MAIN_MENU';
      await ctx.reply(
        `🔍 <b>Info-Gathering Scan Queued!</b>\n\n` +
        `• <b>Target:</b> <code>${escapeHtml(text)}</code>\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Job ID:</b> <code>${jobId}</code>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    }
    else if (step === 'WEB_INPUT') {
      const jobId = await triggerScan(ctx, 'web', text, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      ctx.session.step = 'MAIN_MENU';
      await ctx.reply(
        `🌐 <b>Web Recon & Crawl Queued!</b>\n\n` +
        `• <b>Target:</b> <code>${escapeHtml(text)}</code>\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Job ID:</b> <code>${jobId}</code>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    }
    else if (step === 'NET_INPUT') {
      const jobId = await triggerScan(ctx, 'network', text, runner);
      if (!jobId) return; // scan denied by scope/role (reply already sent)
      ctx.session.step = 'MAIN_MENU';
      await ctx.reply(
        `🔌 <b>Network & Port Scan Queued!</b>\n\n` +
        `• <b>Target:</b> <code>${escapeHtml(text)}</code>\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Job ID:</b> <code>${jobId}</code>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    }
    else if (step === 'ADD_DOMAIN_INPUT') {
      const companyId = ctx.session.target_company_id;
      const host = text.toLowerCase().trim();
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(host);
      if (!isDomain) {
        return await ctx.reply("❌ Invalid domain format. Please send a valid domain (e.g. <code>api.example.com</code>):", { parse_mode: "HTML" });
      }

      const id = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO domains (id, company_id, host, canonical_url, data) VALUES (?, ?, ?, ?, '{}') ON CONFLICT(company_id, lower(host)) DO NOTHING"
      ).bind(id, companyId, host, `http://${host}`).run();

      ctx.session.step = 'MAIN_MENU';
      ctx.session.target_company_id = null;

      await ctx.reply(`✅ Domain <code>${escapeHtml(host)}</code> added to company!`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "🌐 View Company Domains", callback_data: `view_company_domains_${companyId}_0` }],
            [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
          ]
        }
      });
    }
    else if (step === 'RENAME_RUNNER') {
      const oldRunnerName = ctx.session.target_runner;
      const newRunnerName = text.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9_-]/g, '');
      if (!newRunnerName || newRunnerName.length < 2) {
        return await ctx.reply("❌ Invalid runner name. Use alphanumeric characters, dashes, and underscores. Please send a new name:");
      }

      try {
        const existing = await env.DB.prepare("SELECT name FROM runners WHERE name = ?").bind(newRunnerName).first();
        if (existing) {
          return await ctx.reply(`❌ A runner named <code>${escapeHtml(newRunnerName)}</code> already exists. Please send a different name:`, { parse_mode: "HTML" });
        }

        await env.DB.prepare("UPDATE runners SET name = ?, last_seen = strftime('%s', 'now') WHERE name = ?").bind(newRunnerName, oldRunnerName).run();
        await env.DB.prepare("UPDATE scan_jobs SET runner = ? WHERE runner = ?").bind(newRunnerName, oldRunnerName).run();

        if (ctx.session.selected_runner === oldRunnerName) {
          ctx.session.selected_runner = newRunnerName;
        }

        ctx.session.step = 'MAIN_MENU';
        ctx.session.target_runner = null;

        await ctx.reply(`✅ Runner <code>${escapeHtml(oldRunnerName)}</code> successfully renamed to <code>${escapeHtml(newRunnerName)}</code>.`, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Go to Runners", callback_data: "change_runner" }]]
          }
        });
      } catch (err) {
        console.error("D1 error in rename runner:", err.message);
        await ctx.reply(`❌ Database error while renaming runner: ${escapeHtml(err.message)}`);
      }
    } 
    else {
      // Default fallback: if a domain is pasted directly, start recon scan
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(text);
      if (isDomain) {
        const jobId = await triggerScan(ctx, 'domain', text, runner);
        if (!jobId) return; // scan denied by scope/role (reply already sent)
        await ctx.reply(
          `🚀 <b>Full Recon Scan Queued!</b>\n\n` +
          `• <b>Target:</b> <code>${escapeHtml(text)}</code>\n` +
          `• <b>Runner:</b> <code>${runner}</code>\n` +
          `• <b>Job ID:</b> <code>${jobId}</code>`,
          {
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "📜 View Live Job", callback_data: `manage_job:${jobId}` }],
                [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
              ]
            }
          }
        );
      } else {
        const menuMarkup = await createMainMenu(ctx, env);
        await ctx.reply("To start an operation, choose an option from the menu or send a domain to scan:", {
          reply_markup: menuMarkup
        });
      }
    }
  });

  // Global grammY error catcher
  bot.catch((err) => {
    const ctx = err.ctx;
    console.error(`Error while handling update ${ctx.update?.update_id}:`);
    const e = err.error;
    if (e && e.description && e.description.includes("message is not modified")) {
      return;
    }
    console.error(e);
  });

  return bot;
};

// ----------------------------------------------------
// Unified Hono Web Application & Router
// ----------------------------------------------------
const app = new Hono();

// ----------------------------------------------------
// Authentication: shared-secret bearer token
// ----------------------------------------------------
// Constant-time string comparison to avoid timing side-channels.
const safeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
};

// Control-plane auth model (reconciled):
//   * GraphQL is role-enforced inside resolvers via requireRole(), active when
//     AUTH_ENFORCED=true (per-user API tokens); open in single-operator mode.
//   * Runner + DB admin endpoints are gated by the RUNNER_TOKEN shared secret
//     through runnerTokenOk() below (bootstrap-open until the token is set).
//   * No wildcard CORS: these endpoints are server-to-server + the Telegram
//     webhook, so no browser origin should be able to read them.

// Runner endpoints accept a shared secret when RUNNER_TOKEN is configured.
// When it is unset, access stays open so existing deployments keep working.
const runnerTokenOk = (c) => {
  const expected = c.env.RUNNER_TOKEN;
  if (!expected) return true; // bootstrap mode
  const hdr = c.req.header('x-runner-token') || '';
  const auth = c.req.header('authorization') || '';
  const bearer = /^Bearer\s+/i.test(auth) ? auth.replace(/^Bearer\s+/i, '').trim() : '';
  return hdr === expected || bearer === expected;
};

// ----------------------------------------------------
// Telegram Mini App (Web App)
// ----------------------------------------------------
// A Mini App is an HTML page Telegram opens inside the client. It authenticates
// the viewer with the `initData` string Telegram injects, which we verify
// server-side against the bot token (HMAC-SHA256) before trusting any user id.
// Docs: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app

const hmacSha256Bytes = async (keyBytes, msgBytes) => {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, msgBytes));
};

// Reject initData older than this to limit replay of a leaked payload.
const MINIAPP_MAX_AGE_SECS = 86400; // 24h

// Verify a Telegram Mini App initData string. Returns { ok, user, authDate };
// ok=false on a missing/forged hash or a stale auth_date.
const validateInitData = async (initData, botToken) => {
  if (!initData || !botToken) return { ok: false };
  const params = new URLSearchParams(initData);
  const hash = params.get('hash') || '';
  if (!hash) return { ok: false };
  params.delete('hash');

  // data-check-string: remaining pairs, key-sorted, joined by newlines.
  const pairs = [...params.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join('\n');

  const enc = new TextEncoder();
  const secretKey = await hmacSha256Bytes(enc.encode('WebAppData'), enc.encode(botToken));
  const sig = await hmacSha256Bytes(secretKey, enc.encode(dataCheckString));
  const hex = [...sig].map((b) => b.toString(16).padStart(2, '0')).join('');
  if (!safeEqual(hex, hash)) return { ok: false };

  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || (Date.now() / 1000) - authDate > MINIAPP_MAX_AGE_SECS) {
    return { ok: false, reason: 'stale' };
  }

  let user = null;
  try { user = JSON.parse(params.get('user') || 'null'); } catch (_) { /* ignore */ }
  return { ok: true, user, authDate };
};

// Authorize a Mini App request: pull initData from the Authorization header
// ("tma <initData>") or X-Telegram-Init-Data, verify it, then apply the same
// RBAC gate the bot uses (minimum viewer, or any team membership).
const authorizeMiniApp = async (c) => {
  const auth = c.req.header('authorization') || '';
  let initData = /^tma\s+/i.test(auth) ? auth.replace(/^tma\s+/i, '').trim() : '';
  if (!initData) initData = c.req.header('x-telegram-init-data') || '';

  const res = await validateInitData(initData, c.env.TELEGRAM_BOT_TOKEN);
  if (!res.ok || !res.user) return { ok: false };

  const actor = await resolveActor(c.env, res.user);
  const admitted = actor.hasGlobal('viewer') || actor.memberships.length > 0;
  if (!admitted) return { ok: false, actor, pending: true };
  return { ok: true, actor, user: res.user };
};

// Gather the same figures the /dashboard bot command shows, as plain JSON.
const collectDashboardStats = async (env) => {
  const cnt = async (sql, ...b) =>
    (await env.DB.prepare(sql).bind(...b).first())?.cnt || 0;
  const companies = await cnt("SELECT count(*) as cnt FROM companies");
  const domains = await cnt("SELECT count(*) as cnt FROM domains");
  const people = await cnt("SELECT count(*) as cnt FROM people");
  const { results: findings } = await env.DB.prepare("SELECT severity, status FROM findings").all();
  const sev = (s) => findings.filter((f) => f.severity?.toLowerCase() === s).length;
  const secrets = await cnt("SELECT count(*) as cnt FROM secrets");
  const services = await cnt("SELECT count(*) as cnt FROM network_services");
  const activeJobs = await cnt("SELECT count(*) as cnt FROM scan_jobs WHERE status IN ('pending','running')");
  const cutoff = Math.floor(Date.now() / 1000) - 60;
  const runnersOnline = await cnt("SELECT count(*) as cnt FROM runners WHERE last_seen >= ?", cutoff);
  const runnersTotal = await cnt("SELECT count(*) as cnt FROM runners");

  const rows = async (sql, ...b) =>
    (await env.DB.prepare(sql).bind(...b).all())?.results || [];

  // Findings discovered per day, last 14 days (change-over-time series). ISO
  // created_at sorts lexically, so a date-only lower bound filters correctly.
  const sinceDay = new Date(Date.now() - 13 * 86400000).toISOString().slice(0, 10);
  const trend = await rows(
    "SELECT substr(created_at,1,10) AS day, count(*) AS cnt FROM findings " +
    "WHERE created_at >= ? GROUP BY day ORDER BY day", sinceDay
  );
  // Scan queue composition by state (part-to-whole).
  const jobs = await rows("SELECT status, count(*) AS cnt FROM scan_jobs GROUP BY status");
  // Top targets by finding count (magnitude + identity ranking).
  const topTargets = await rows(
    "SELECT c.name AS name, count(f.id) AS cnt FROM companies c " +
    "LEFT JOIN findings f ON f.company_id = c.id " +
    "GROUP BY c.id ORDER BY cnt DESC, c.name LIMIT 5"
  );
  // Most common open ports (magnitude ranking).
  const topPorts = await rows(
    "SELECT port, count(*) AS cnt FROM network_services GROUP BY port ORDER BY cnt DESC, port LIMIT 6"
  );

  return {
    companies, domains, people,
    findings: {
      total: findings.length,
      critical: sev('critical'), high: sev('high'), medium: sev('medium'),
      low: sev('low'), info: sev('info'),
      resolved: findings.filter((f) => f.status === 'resolved').length,
    },
    secrets, services, activeJobs, runnersOnline, runnersTotal,
    trend, jobs, topTargets, topPorts, sinceDay,
  };
};

// Self-contained Mini App shell. Verified data is loaded client-side from
// /app/api/summary with the viewer's initData in the Authorization header.
// Charts are hand-built inline SVG / CSS (no CDN) so the page stays one request.
// Color: severity + job status are a STATUS palette (reserved hues, always shown
// WITH labels + counts in ink, never color-alone); trend and ranking charts are
// single-hue. Values/labels wear ink tokens; marks carry the only color.
const MINIAPP_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover" />
<title>cHack Intel</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
  /* ---- Design tokens (dark default; light via [data-theme=light]). Palette is
     the validated data-viz reference: categorical slots 1-3 for node types,
     fixed status palette for severity, blue sequential for trend/ranking. ---- */
  :root{
    color-scheme: dark;
    --plane:#0d0d0d; --surface:#1a1a19; --surface-2:#232321; --surface-3:#2b2b28;
    --ink:#f0efec; --ink-2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --axis:#383835; --border:rgba(255,255,255,.10);
    --c-company:#3987e5; --c-domain:#199e70; --c-person:#d95926;
    --s-crit:#d03b3b; --s-high:#ec835a; --s-med:#fab219; --s-low:#0ca30c; --s-info:#5a6b7a;
    --seq:#3987e5;
    --radius:16px; --gap:14px;
    --font: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  :root[data-theme="light"]{
    color-scheme: light;
    --plane:#f9f9f7; --surface:#fcfcfb; --surface-2:#f1f1ee; --surface-3:#e9e9e4;
    --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781;
    --grid:#e1e0d9; --axis:#c3c2b7; --border:rgba(11,11,11,.10);
    --c-company:#2a78d6; --c-domain:#1baf7a; --c-person:#eb6834;
    --seq:#2a78d6;
  }
  *{ box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
  html,body{ margin:0; padding:0; background:var(--plane); color:var(--ink);
    font-family:var(--font); font-size:15px; line-height:1.4;
    -webkit-font-smoothing:antialiased; overscroll-behavior:none; }
  #app{ max-width:720px; margin:0 auto; padding:0 16px
    calc(28px + env(safe-area-inset-bottom)); min-height:100vh; }

  /* Header */
  header.hd{ position:sticky; top:0; z-index:20; background:var(--plane);
    padding:14px 0 10px; display:flex; align-items:center; gap:12px; }
  .mark{ width:34px; height:34px; border-radius:10px; flex:0 0 auto;
    background:linear-gradient(135deg,var(--c-company),var(--c-domain));
    display:grid; place-items:center; color:#fff; font-weight:800; font-size:16px;
    box-shadow:0 2px 10px rgba(0,0,0,.35); }
  .hd h1{ font-size:17px; margin:0; letter-spacing:.2px; }
  .hd .sub{ color:var(--muted); font-size:11.5px; margin-top:1px; }
  .hd .spacer{ flex:1; }
  .chip-role{ font-size:11px; color:var(--ink-2); background:var(--surface-2);
    border:1px solid var(--border); padding:4px 9px; border-radius:999px;
    white-space:nowrap; text-transform:capitalize; }
  .iconbtn{ width:34px; height:34px; border-radius:10px; border:1px solid var(--border);
    background:var(--surface-2); color:var(--ink-2); display:grid; place-items:center;
    font-size:15px; cursor:pointer; }
  .iconbtn:active{ transform:scale(.94); }

  /* Tabs (custom segmented control) */
  nav.tabs{ position:sticky; top:62px; z-index:15; background:var(--plane);
    padding:4px 0 12px; display:grid; grid-template-columns:repeat(4,1fr); gap:6px; }
  nav.tabs button{ appearance:none; border:1px solid var(--border);
    background:var(--surface); color:var(--ink-2); border-radius:11px;
    padding:9px 4px; font:inherit; font-size:12.5px; font-weight:600; cursor:pointer;
    transition:background .12s, color .12s, border-color .12s; }
  nav.tabs button[aria-selected="true"]{ background:var(--surface-3); color:var(--ink);
    border-color:var(--border); box-shadow:inset 0 0 0 1px var(--border); }
  nav.tabs button:active{ transform:scale(.97); }

  /* Cards + layout */
  .card{ background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); padding:14px; margin-bottom:var(--gap); }
  .card h2{ font-size:13px; font-weight:700; color:var(--ink); margin:0 0 2px; }
  .card .cap{ font-size:11.5px; color:var(--muted); margin:0 0 12px; }
  .grid-tiles{ display:grid; grid-template-columns:repeat(2,1fr); gap:var(--gap);
    margin-bottom:var(--gap); }
  .tile{ background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); padding:13px 14px; position:relative; overflow:hidden; }
  .tile .k{ font-size:11px; color:var(--muted); font-weight:600;
    text-transform:uppercase; letter-spacing:.4px; }
  .tile .v{ font-size:30px; font-weight:750; margin-top:3px; line-height:1;
    letter-spacing:-.5px; }
  .tile .s{ font-size:11.5px; color:var(--ink-2); margin-top:5px; }
  .tile .accent{ position:absolute; left:0; top:0; bottom:0; width:3px; }

  /* Labeled severity rows */
  .sevrow{ display:grid; grid-template-columns:70px 1fr 34px; align-items:center;
    gap:10px; margin:7px 0; }
  .sevrow .lab{ display:flex; align-items:center; gap:7px; font-size:12px; color:var(--ink-2); }
  .dot{ width:9px; height:9px; border-radius:3px; flex:0 0 auto; }
  .track{ height:9px; background:var(--surface-2); border-radius:5px; overflow:hidden; }
  .fill{ height:100%; border-radius:5px; }
  .sevrow .num{ font-size:12.5px; color:var(--ink); text-align:right;
    font-variant-numeric:tabular-nums; font-weight:650; }

  /* Ranking bars */
  .rank{ display:grid; grid-template-columns:1fr; gap:9px; }
  .rank .row{ display:grid; grid-template-columns:1fr; gap:4px; }
  .rank .top{ display:flex; justify-content:space-between; font-size:12.5px; }
  .rank .top .nm{ color:var(--ink-2); overflow:hidden; text-overflow:ellipsis;
    white-space:nowrap; max-width:74%; }
  .rank .top .vl{ color:var(--ink); font-weight:650; font-variant-numeric:tabular-nums; }
  .rank .bar{ height:8px; background:var(--surface-2); border-radius:4px; overflow:hidden; }
  .rank .bar i{ display:block; height:100%; border-radius:4px; background:var(--seq); }

  /* Company / people list cards */
  .listcard{ background:var(--surface); border:1px solid var(--border);
    border-radius:14px; padding:12px 13px; margin-bottom:11px; }
  .listcard .r1{ display:flex; align-items:baseline; gap:8px; }
  .listcard .name{ font-size:14px; font-weight:700; overflow:hidden;
    text-overflow:ellipsis; white-space:nowrap; }
  .listcard .r1 .big{ margin-left:auto; font-size:20px; font-weight:750;
    font-variant-numeric:tabular-nums; }
  .listcard .r1 .big small{ font-size:11px; color:var(--muted); font-weight:600;
    margin-left:3px; }
  .chips{ display:flex; flex-wrap:wrap; gap:6px; margin-top:9px; }
  .chip{ font-size:11px; color:var(--ink-2); background:var(--surface-2);
    border:1px solid var(--border); border-radius:8px; padding:3px 8px;
    display:inline-flex; align-items:center; gap:5px; font-variant-numeric:tabular-nums; }
  .chip b{ color:var(--ink); font-weight:650; }
  .microbar{ display:flex; height:7px; border-radius:4px; overflow:hidden;
    margin-top:10px; background:var(--surface-2); gap:2px; }
  .microbar i{ height:100%; }

  /* Search */
  .search{ position:relative; margin-bottom:12px; }
  .search input{ width:100%; background:var(--surface); color:var(--ink);
    border:1px solid var(--border); border-radius:12px; padding:11px 12px 11px 34px;
    font:inherit; font-size:14px; outline:none; }
  .search input:focus{ border-color:var(--c-company); }
  .search .ic{ position:absolute; left:11px; top:50%; transform:translateY(-50%);
    color:var(--muted); font-size:14px; }

  /* Graph / map */
  .maptools{ display:flex; align-items:center; gap:8px; margin-bottom:10px;
    flex-wrap:wrap; }
  .legend{ display:flex; gap:12px; flex-wrap:wrap; }
  .legend span{ display:inline-flex; align-items:center; gap:6px; font-size:12px;
    color:var(--ink-2); }
  .graphwrap{ position:relative; background:var(--surface); border:1px solid var(--border);
    border-radius:var(--radius); overflow:hidden; height:62vh; min-height:380px;
    touch-action:none; }
  .graphwrap svg{ width:100%; height:100%; display:block; cursor:grab; }
  .graphwrap svg:active{ cursor:grabbing; }
  .gnode-label{ font-size:10px; fill:var(--ink-2); pointer-events:none;
    paint-order:stroke; stroke:var(--surface); stroke-width:3px; }
  .gcount{ position:absolute; left:10px; bottom:9px; font-size:11px; color:var(--muted);
    background:var(--surface-2); border:1px solid var(--border); padding:3px 8px;
    border-radius:8px; pointer-events:none; }

  /* Tooltip */
  #tooltip{ position:fixed; z-index:50; pointer-events:none; opacity:0;
    transform:translate(-50%,-115%); transition:opacity .08s;
    background:var(--surface-3); color:var(--ink); border:1px solid var(--border);
    border-radius:9px; padding:7px 9px; font-size:12px; max-width:220px;
    box-shadow:0 6px 20px rgba(0,0,0,.4); }
  #tooltip .tt-t{ font-weight:700; margin-bottom:2px; }
  #tooltip .tt-s{ color:var(--ink-2); font-size:11.5px; }

  /* States */
  .empty{ text-align:center; color:var(--muted); padding:34px 10px; font-size:13px; }
  .skel{ background:linear-gradient(90deg,var(--surface-2),var(--surface-3),var(--surface-2));
    background-size:200% 100%; animation:sh 1.1s linear infinite; border-radius:10px; }
  @keyframes sh{ 0%{background-position:200% 0} 100%{background-position:-200% 0} }
  .muted{ color:var(--muted); }
  .axislab{ font-size:10px; fill:var(--muted); }
  .seg-hidden{ display:none; }
  table.tbl{ width:100%; border-collapse:collapse; font-size:12.5px; }
  table.tbl th,table.tbl td{ text-align:left; padding:8px 6px; border-bottom:1px solid var(--grid);
    font-variant-numeric:tabular-nums; }
  table.tbl th{ color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase;
    letter-spacing:.3px; }
  table.tbl td.r,table.tbl th.r{ text-align:right; }
  .viewtoggle{ display:flex; gap:6px; margin-left:auto; }
  .viewtoggle button{ font-size:11px; padding:5px 10px; border-radius:8px;
    border:1px solid var(--border); background:var(--surface-2); color:var(--ink-2); cursor:pointer; }
  .viewtoggle button[aria-pressed="true"]{ background:var(--surface-3); color:var(--ink); }
</style>
</head>
<body>
<div id="app">
  <header class="hd">
    <div class="mark">cH</div>
    <div>
      <h1>cHack Intel</h1>
      <div class="sub" id="sub">Loading intelligence…</div>
    </div>
    <div class="spacer"></div>
    <span class="chip-role" id="role" hidden></span>
    <button class="iconbtn" id="refresh" title="Refresh" aria-label="Refresh">&#x21bb;</button>
  </header>

  <nav class="tabs" role="tablist">
    <button role="tab" data-view="overview" aria-selected="true">Overview</button>
    <button role="tab" data-view="companies" aria-selected="false">Companies</button>
    <button role="tab" data-view="people" aria-selected="false">People</button>
    <button role="tab" data-view="map" aria-selected="false">Map</button>
  </nav>

  <main>
    <section id="view-overview"></section>
    <section id="view-companies" hidden></section>
    <section id="view-people" hidden></section>
    <section id="view-map" hidden></section>
  </main>
</div>
<div id="tooltip" role="tooltip"></div>

<script>
(function(){
  "use strict";
  var tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  if (tg) { try { tg.ready(); tg.expand(); } catch(e){} }

  // Theme: follow Telegram's color scheme; default dark.
  function applyTheme(){
    var scheme = tg && tg.colorScheme ? tg.colorScheme : 'dark';
    document.documentElement.setAttribute('data-theme', scheme === 'light' ? 'light' : 'dark');
  }
  applyTheme();
  if (tg && tg.onEvent) { try { tg.onEvent('themeChanged', applyTheme); } catch(e){} }

  var initData = (tg && tg.initData) || '';
  var AUTH = { 'Authorization': 'tma ' + initData };
  var SEV = [
    { k:'critical', lab:'Critical', c:'var(--s-crit)' },
    { k:'high',     lab:'High',     c:'var(--s-high)' },
    { k:'medium',   lab:'Medium',   c:'var(--s-med)'  },
    { k:'low',      lab:'Low',      c:'var(--s-low)'  },
    { k:'info',     lab:'Info',     c:'var(--s-info)' }
  ];
  var TYPE = { company:'var(--c-company)', domain:'var(--c-domain)', person:'var(--c-person)' };

  var cache = {};           // endpoint -> json
  var el = function(id){ return document.getElementById(id); };
  var esc = function(s){ return String(s==null?'':s).replace(/[&<>"]/g, function(ch){
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[ch]; }); };
  var nf = function(n){ return (n==null?0:n).toLocaleString(); };

  function api(path, cb){
    if (cache[path]) { cb(null, cache[path]); return; }
    fetch(path, { headers: AUTH }).then(function(r){
      return r.json().then(function(j){ return { status:r.status, body:j }; });
    }).then(function(res){
      if (res.status === 401) { cb({ pending: res.body && res.body.error === 'pending' }, null); return; }
      if (!res.body || res.body.ok === false || res.body.error) { cb(res.body || { error:'error' }, null); return; }
      cache[path] = res.body; cb(null, res.body);
    }).catch(function(e){ cb({ error:e.message }, null); });
  }

  // ---- Tooltip ----
  var tip = el('tooltip');
  function showTip(x, y, title, sub){
    tip.innerHTML = '<div class="tt-t">' + esc(title) + '</div>' +
      (sub ? '<div class="tt-s">' + esc(sub) + '</div>' : '');
    tip.style.left = x + 'px'; tip.style.top = y + 'px'; tip.style.opacity = '1';
  }
  function hideTip(){ tip.style.opacity = '0'; }

  // ---- Tab switching ----
  var VIEWS = ['overview','companies','people','map'];
  var loaded = {};
  function selectView(v){
    VIEWS.forEach(function(name){
      el('view-' + name).hidden = (name !== v);
    });
    document.querySelectorAll('nav.tabs button').forEach(function(b){
      b.setAttribute('aria-selected', b.getAttribute('data-view') === v ? 'true' : 'false');
    });
    hideTip();
    if (!loaded[v]) { loaded[v] = true; render[v](); }
    window.scrollTo(0, 0);
  }
  document.querySelectorAll('nav.tabs button').forEach(function(b){
    b.addEventListener('click', function(){
      if (tg && tg.HapticFeedback) { try { tg.HapticFeedback.selectionChanged(); } catch(e){} }
      selectView(b.getAttribute('data-view'));
    });
  });

  // ---- SVG helpers ----
  function svg(tag, attrs){
    var e = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  // =====================================================================
  //  OVERVIEW
  // =====================================================================
  function tile(k, v, s, accent){
    return '<div class="tile">' + (accent ? '<div class="accent" style="background:'+accent+'"></div>' : '') +
      '<div class="k">' + esc(k) + '</div><div class="v">' + nf(v) + '</div>' +
      (s ? '<div class="s">' + esc(s) + '</div>' : '') + '</div>';
  }

  function severityCard(f){
    var total = f.total || 0;
    var max = Math.max(f.critical, f.high, f.medium, f.low, f.info, 1);
    var rows = SEV.map(function(s){
      var n = f[s.k] || 0;
      var w = Math.round((n / max) * 100);
      return '<div class="sevrow"><div class="lab"><span class="dot" style="background:'+s.c+'"></span>'+s.lab+'</div>'+
        '<div class="track"><div class="fill" style="width:'+w+'%;background:'+s.c+'"></div></div>'+
        '<div class="num">'+nf(n)+'</div></div>';
    }).join('');
    return '<div class="card"><h2>Findings by severity</h2>'+
      '<p class="cap">'+nf(total)+' findings total &middot; '+nf(f.resolved||0)+' resolved</p>'+rows+'</div>';
  }

  function trendCard(trend, sinceDay){
    var W = 320, H = 110, pad = { l:6, r:6, t:10, b:16 };
    // Normalize to 14 continuous days.
    var map = {}; (trend||[]).forEach(function(d){ map[d.day] = d.cnt; });
    var days = [], base = new Date(sinceDay + 'T00:00:00Z');
    for (var i=0;i<14;i++){ var d=new Date(base.getTime()+i*86400000);
      var key=d.toISOString().slice(0,10); days.push({ day:key, cnt: map[key]||0 }); }
    var max = Math.max.apply(null, days.map(function(d){ return d.cnt; }).concat([1]));
    var iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
    var X = function(i){ return pad.l + (days.length<2?iw/2:(i/(days.length-1))*iw); };
    var Y = function(v){ return pad.t + ih - (v/max)*ih; };
    var line = '', area = 'M' + X(0) + ' ' + Y(days[0].cnt);
    days.forEach(function(d,i){ var c=(i===0?'M':'L')+X(i)+' '+Y(d.cnt); line+=c;
      if(i>0) area += 'L'+X(i)+' '+Y(d.cnt); });
    area += 'L'+X(days.length-1)+' '+(pad.t+ih)+'L'+X(0)+' '+(pad.t+ih)+'Z';
    var totalN = days.reduce(function(a,d){ return a+d.cnt; },0);
    var dots = days.map(function(d,i){ return '<circle cx="'+X(i)+'" cy="'+Y(d.cnt)+'" r="2.4" fill="var(--seq)"/>'; }).join('');
    var grid = '';
    for (var g=0; g<=2; g++){ var yy = pad.t + (g/2)*ih;
      grid += '<line x1="'+pad.l+'" y1="'+yy+'" x2="'+(W-pad.r)+'" y2="'+yy+'" stroke="var(--grid)" stroke-width="1"/>'; }
    var html = '<div class="card"><h2>Findings &mdash; last 14 days</h2>'+
      '<p class="cap">'+nf(totalN)+' new &middot; peak '+nf(max)+'/day</p>'+
      '<svg viewBox="0 0 '+W+' '+H+'" width="100%" preserveAspectRatio="none" id="trendSvg" style="overflow:visible">'+
      grid +
      '<path d="'+area+'" fill="var(--seq)" opacity="0.14"/>'+
      '<path d="'+line+'" fill="none" stroke="var(--seq)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'+
      dots +
      '<line id="trendCross" x1="0" y1="'+pad.t+'" x2="0" y2="'+(pad.t+ih)+'" stroke="var(--axis)" stroke-width="1" opacity="0"/>'+
      '<text class="axislab" x="'+pad.l+'" y="'+H+'">'+days[0].day.slice(5)+'</text>'+
      '<text class="axislab" x="'+(W-pad.r)+'" y="'+H+'" text-anchor="end">'+days[days.length-1].day.slice(5)+'</text>'+
      '</svg></div>';
    return { html:html, days:days, X:X, Y:Y, pad:pad, ih:ih };
  }

  function rankingCard(title, rows, unit){
    if (!rows || !rows.length) return '<div class="card"><h2>'+esc(title)+'</h2><div class="empty">No data yet.</div></div>';
    var max = Math.max.apply(null, rows.map(function(r){ return r.cnt; }).concat([1]));
    var body = rows.map(function(r){
      var w = Math.round((r.cnt/max)*100);
      return '<div class="row"><div class="top"><span class="nm">'+esc(r.name!=null?r.name:r.port)+'</span>'+
        '<span class="vl">'+nf(r.cnt)+'</span></div>'+
        '<div class="bar"><i style="width:'+Math.max(w,2)+'%"></i></div></div>';
    }).join('');
    return '<div class="card"><h2>'+esc(title)+'</h2><p class="cap">by '+esc(unit)+'</p><div class="rank">'+body+'</div></div>';
  }

  var render = {};
  render.overview = function(){
    var box = el('view-overview');
    box.innerHTML = skeletonTiles() + '<div class="card skel" style="height:150px"></div>';
    api('/app/api/summary', function(err, data){
      if (err) { box.innerHTML = errorHtml(err); return; }
      var s = data.stats;
      el('sub').textContent = nf(s.companies)+' targets · '+nf(s.findings.total)+' findings';
      if (data.viewer && data.viewer.role){ var rc=el('role'); rc.hidden=false; rc.textContent=data.viewer.role; }
      var tiles = '<div class="grid-tiles">' +
        tile('Companies', s.companies, nf(s.domains)+' domains', 'var(--c-company)') +
        tile('People', s.people, 'associates mapped', 'var(--c-person)') +
        tile('Findings', s.findings.total, nf(s.findings.critical+s.findings.high)+' crit/high', 'var(--s-crit)') +
        tile('Secrets', s.secrets, nf(s.services)+' services', 'var(--c-domain)') +
      '</div>';
      var opsTile = '<div class="grid-tiles">'+
        tile('Active jobs', s.activeJobs, 'in the queue', 'var(--s-med)')+
        tile('Runners', s.runnersOnline, s.runnersOnline+' of '+s.runnersTotal+' online', 'var(--s-low)')+
      '</div>';
      var tc = trendCard(s.trend, s.sinceDay);
      box.innerHTML = tiles + severityCard(s.findings) + tc.html +
        rankingCard('Top targets', s.topTargets, 'finding count') +
        rankingCard('Common open ports', (s.topPorts||[]).map(function(p){ return { name:'Port '+p.port, cnt:p.cnt }; }), 'service count') +
        opsTile;
      wireTrendHover(tc);
    });
  };

  function wireTrendHover(tc){
    var sv = el('trendSvg'); if (!sv) return;
    var cross = el('trendCross');
    sv.addEventListener('pointermove', function(ev){
      var r = sv.getBoundingClientRect();
      var rel = (ev.clientX - r.left) / r.width * 320;
      var i = Math.round((rel - tc.pad.l) / (320 - tc.pad.l - 6) * (tc.days.length - 1));
      i = Math.max(0, Math.min(tc.days.length - 1, i));
      var d = tc.days[i];
      cross.setAttribute('x1', tc.X(i)); cross.setAttribute('x2', tc.X(i)); cross.setAttribute('opacity','0.8');
      showTip(ev.clientX, r.top + tc.Y(d.cnt), d.cnt + ' finding' + (d.cnt===1?'':'s'), d.day);
    });
    sv.addEventListener('pointerleave', function(){ cross.setAttribute('opacity','0'); hideTip(); });
  }

  // =====================================================================
  //  COMPANIES
  // =====================================================================
  render.companies = function(){
    var box = el('view-companies');
    box.innerHTML = '<div class="search"><span class="ic">&#x1F50D;</span>'+
      '<input id="cq" placeholder="Search companies…" autocomplete="off"></div>'+
      '<div id="clist">'+skeletonCards(4)+'</div>';
    api('/app/api/companies', function(err, data){
      if (err) { el('clist').innerHTML = errorHtml(err); return; }
      var all = data.companies || [];
      function draw(q){
        var list = all.filter(function(c){ return !q || (c.name||'').toLowerCase().indexOf(q)>=0; });
        if (!list.length){ el('clist').innerHTML = '<div class="empty">No companies'+(q?' match &ldquo;'+esc(q)+'&rdquo;':' yet')+'.</div>'; return; }
        el('clist').innerHTML = list.map(companyCard).join('');
        bindTipTargets(el('clist'));
      }
      draw('');
      el('cq').addEventListener('input', function(e){ draw(e.target.value.trim().toLowerCase()); });
    });
  };
  function companyCard(c){
    var sevs = [['critical',c.crit,'var(--s-crit)'],['high',c.high,'var(--s-high)'],
      ['medium',c.med,'var(--s-med)'],['low',c.low,'var(--s-low)'],['info',c.info,'var(--s-info)']];
    var tot = (c.crit||0)+(c.high||0)+(c.med||0)+(c.low||0)+(c.info||0);
    var micro = tot ? '<div class="microbar">'+ sevs.map(function(s){
      var w=(s[1]||0)/tot*100; return w>0?'<i style="width:'+w+'%;background:'+s[2]+'" data-tt="'+esc(s[0])+': '+(s[1]||0)+'"></i>':''; }).join('') +'</div>' : '';
    return '<div class="listcard">'+
      '<div class="r1"><span class="name">'+esc(c.name||'(unnamed)')+'</span>'+
        '<span class="big">'+nf(c.findings||0)+'<small>findings</small></span></div>'+
      '<div class="chips">'+
        '<span class="chip"><span class="dot" style="background:var(--c-domain)"></span><b>'+nf(c.domains||0)+'</b> domains</span>'+
        '<span class="chip"><span class="dot" style="background:var(--c-person)"></span><b>'+nf(c.people||0)+'</b> people</span>'+
        (c.crit? '<span class="chip"><span class="dot" style="background:var(--s-crit)"></span><b>'+nf(c.crit)+'</b> critical</span>':'')+
        (c.high? '<span class="chip"><span class="dot" style="background:var(--s-high)"></span><b>'+nf(c.high)+'</b> high</span>':'')+
      '</div>'+ micro +'</div>';
  }

  // =====================================================================
  //  PEOPLE
  // =====================================================================
  var peopleMode = 'cards';
  render.people = function(){
    var box = el('view-people');
    box.innerHTML = '<div id="pstat"></div>'+
      '<div class="search"><span class="ic">&#x1F50D;</span>'+
      '<input id="pq" placeholder="Search people / companies…" autocomplete="off"></div>'+
      '<div style="display:flex;align-items:center;margin-bottom:10px">'+
        '<span class="muted" style="font-size:12px" id="pcount"></span>'+
        '<span class="viewtoggle"><button id="pcards" aria-pressed="true">Cards</button>'+
        '<button id="ptable" aria-pressed="false">Table</button></span></div>'+
      '<div id="plist">'+skeletonCards(4)+'</div>';
    api('/app/api/people', function(err, data){
      if (err) { el('plist').innerHTML = errorHtml(err); return; }
      var all = data.people || [];
      var withBreach = all.filter(function(p){ return p.breaches>0; }).length;
      var withAcc = all.reduce(function(a,p){ return a+(p.accounts||0); },0);
      el('pstat').innerHTML = '<div class="grid-tiles">'+
        tile('People', all.length, 'associates mapped', 'var(--c-person)')+
        tile('Breached', withBreach, nf(withAcc)+' accounts found', 'var(--s-crit)')+'</div>';
      function draw(q){
        var list = all.filter(function(p){ return !q ||
          (p.name||'').toLowerCase().indexOf(q)>=0 || (p.company||'').toLowerCase().indexOf(q)>=0; });
        el('pcount').textContent = list.length + ' shown';
        if (!list.length){ el('plist').innerHTML='<div class="empty">No people'+(q?' match':' yet')+'.</div>'; return; }
        el('plist').innerHTML = peopleMode==='table' ? peopleTable(list) : list.map(personCard).join('');
      }
      draw('');
      el('pq').addEventListener('input', function(e){ draw(e.target.value.trim().toLowerCase()); });
      function setMode(m){ peopleMode=m;
        el('pcards').setAttribute('aria-pressed', m==='cards'); el('ptable').setAttribute('aria-pressed', m==='table');
        draw(el('pq').value.trim().toLowerCase()); }
      el('pcards').addEventListener('click', function(){ setMode('cards'); });
      el('ptable').addEventListener('click', function(){ setMode('table'); });
    });
  };
  function personCard(p){
    var initials = (p.name||'?').split(/\s+/).map(function(w){return w[0];}).slice(0,2).join('').toUpperCase();
    return '<div class="listcard"><div class="r1">'+
      '<span class="dot" style="width:26px;height:26px;border-radius:8px;display:inline-grid;place-items:center;'+
        'background:var(--surface-3);color:var(--ink-2);font-size:11px;font-weight:700">'+esc(initials)+'</span>'+
      '<span class="name" style="margin-left:9px">'+esc(p.name)+'</span></div>'+
      '<div class="chips">'+
        (p.company? '<span class="chip"><span class="dot" style="background:var(--c-company)"></span>'+esc(p.company)+'</span>':'<span class="chip muted">no company</span>')+
        '<span class="chip"><b>'+nf(p.emails)+'</b> emails</span>'+
        (p.accounts? '<span class="chip"><b>'+nf(p.accounts)+'</b> accounts</span>':'')+
        (p.breaches? '<span class="chip"><span class="dot" style="background:var(--s-crit)"></span><b>'+nf(p.breaches)+'</b> breaches</span>':'')+
      '</div></div>';
  }
  function peopleTable(list){
    var head = '<table class="tbl"><thead><tr><th>Name</th><th>Company</th>'+
      '<th class="r">Emails</th><th class="r">Acct</th><th class="r">Breach</th></tr></thead><tbody>';
    var body = list.map(function(p){ return '<tr><td>'+esc(p.name)+'</td><td class="muted">'+esc(p.company||'—')+'</td>'+
      '<td class="r">'+nf(p.emails)+'</td><td class="r">'+nf(p.accounts)+'</td>'+
      '<td class="r" style="color:'+(p.breaches?'var(--s-crit)':'inherit')+'">'+nf(p.breaches)+'</td></tr>'; }).join('');
    return head + body + '</tbody></table>';
  }

  // =====================================================================
  //  MAP (force-directed connection graph)
  // =====================================================================
  render.map = function(){
    var box = el('view-map');
    box.innerHTML =
      '<div class="maptools"><div class="legend">'+
        '<span><span class="dot" style="background:var(--c-company)"></span>Company</span>'+
        '<span><span class="dot" style="background:var(--c-domain)"></span>Asset</span>'+
        '<span><span class="dot" style="background:var(--c-person)"></span>Associate</span>'+
        '</div><button class="iconbtn" id="gReset" style="margin-left:auto" title="Reset view">&#x2316;</button></div>'+
      '<p class="muted" style="font-size:11.5px;margin:0 0 10px">Each company links to its assets (domains) and associates (people). Drag to pan, pinch/scroll to zoom, tap a node for detail.</p>'+
      '<div class="graphwrap" id="gw"><div class="empty" id="gload">Building graph…</div></div>';
    api('/app/api/graph', function(err, data){
      if (err) { el('gw').innerHTML = errorHtml(err); return; }
      buildGraph(data.nodes || [], data.links || []);
    });
  };

  function buildGraph(nodes, links){
    var wrap = el('gw');
    if (!nodes.length){ wrap.innerHTML = '<div class="empty">No mapped assets yet. Onboard a program and run recon to populate the graph.</div>'; return; }
    // Cap for mobile perf: keep companies + highest-degree neighbours.
    var CAP = 220;
    if (nodes.length > CAP){
      var deg = {}; links.forEach(function(l){ deg[l.s]=(deg[l.s]||0)+1; deg[l.d]=(deg[l.d]||0)+1; });
      nodes.sort(function(a,b){ var ra=a.t==='company'?1e6:0, rb=b.t==='company'?1e6:0;
        return (rb+(deg[b.id]||0)) - (ra+(deg[a.id]||0)); });
      nodes = nodes.slice(0, CAP);
      var keep = {}; nodes.forEach(function(n){ keep[n.id]=1; });
      links = links.filter(function(l){ return keep[l.s] && keep[l.d]; });
    }
    var W = wrap.clientWidth, H = wrap.clientHeight;
    var id2n = {}; nodes.forEach(function(n,i){
      n.x = W/2 + Math.cos(i*2.4)*Math.min(W,H)*0.3*Math.random()+ (Math.random()-0.5)*40;
      n.y = H/2 + Math.sin(i*2.4)*Math.min(W,H)*0.3*Math.random()+ (Math.random()-0.5)*40;
      n.vx=0; n.vy=0; n.deg=0; id2n[n.id]=n; });
    var edges = [];
    links.forEach(function(l){ var s=id2n[l.s], d=id2n[l.d]; if(s&&d){ edges.push({s:s,d:d}); s.deg++; d.deg++; } });

    function radius(n){ if(n.t==='company') return 7 + Math.min(10, Math.sqrt(n.v||0)*1.6);
      return n.t==='domain' ? 4.2 : 4.8; }

    var svgEl = svg('svg', { viewBox:'0 0 '+W+' '+H });
    var gRoot = svg('g', {});
    var gLinks = svg('g', { stroke:'var(--axis)', 'stroke-width':'1', 'stroke-opacity':'0.45' });
    var gNodes = svg('g', {});
    var gLabels = svg('g', {});
    gRoot.appendChild(gLinks); gRoot.appendChild(gNodes); gRoot.appendChild(gLabels);
    svgEl.appendChild(gRoot);
    wrap.innerHTML=''; wrap.appendChild(svgEl);
    var countEl = document.createElement('div'); countEl.className='gcount';
    countEl.textContent = nodes.length + ' nodes · ' + edges.length + ' links';
    wrap.appendChild(countEl);

    var lineEls = edges.map(function(e){ var ln=svg('line',{}); gLinks.appendChild(ln); return ln; });
    var nodeEls = nodes.map(function(n){
      var c = svg('circle', { r:radius(n), fill:TYPE[n.t], stroke:'var(--surface)', 'stroke-width':'1.5' });
      c.style.cursor='pointer';
      c.addEventListener('pointerenter', function(ev){ var rb=wrap.getBoundingClientRect();
        showTip(ev.clientX, ev.clientY, n.label, n.t==='company'? ((n.v||0)+' findings · '+n.deg+' linked') : (n.t+' · linked to company')); });
      c.addEventListener('pointerleave', hideTip);
      c.addEventListener('click', function(ev){ ev.stopPropagation(); var rb=wrap.getBoundingClientRect();
        showTip(ev.clientX, ev.clientY, n.label, n.t==='company'? ((n.v||0)+' findings'):(n.t)); });
      gNodes.appendChild(c); return c;
    });
    // Labels only for companies (avoid clutter).
    var labelEls = nodes.map(function(n){ if(n.t!=='company') return null;
      var t = svg('text', { class:'gnode-label', 'text-anchor':'middle' });
      t.textContent = n.label.length>18 ? n.label.slice(0,17)+'…' : n.label;
      gLabels.appendChild(t); return t; });

    // --- Force simulation (velocity Verlet; cooling alpha) ---
    var alpha = 1, K = Math.sqrt((W*H) / Math.max(nodes.length,1));
    function step(){
      var i,j,a,b,dx,dy,dist,f;
      // Repulsion (O(n^2); node count is capped).
      for (i=0;i<nodes.length;i++){ a=nodes[i];
        for (j=i+1;j<nodes.length;j++){ b=nodes[j];
          dx=a.x-b.x; dy=a.y-b.y; dist=Math.sqrt(dx*dx+dy*dy)||0.5;
          f = (K*K)/(dist*dist) * alpha * 0.9;
          var ux=dx/dist, uy=dy/dist;
          a.vx+=ux*f; a.vy+=uy*f; b.vx-=ux*f; b.vy-=uy*f;
        }
      }
      // Spring attraction along edges.
      for (i=0;i<edges.length;i++){ a=edges[i].s; b=edges[i].d;
        dx=b.x-a.x; dy=b.y-a.y; dist=Math.sqrt(dx*dx+dy*dy)||0.5;
        f = (dist - (a.t==='company'||b.t==='company'?70:40)) * 0.02 * alpha;
        var vx2=dx/dist*f, vy2=dy/dist*f;
        a.vx+=vx2; a.vy+=vy2; b.vx-=vx2; b.vy-=vy2;
      }
      // Gravity to centre + integrate with damping.
      for (i=0;i<nodes.length;i++){ a=nodes[i];
        a.vx += (W/2 - a.x)*0.004*alpha; a.vy += (H/2 - a.y)*0.004*alpha;
        a.vx*=0.86; a.vy*=0.86;
        if (!a.fixed){ a.x+=Math.max(-18,Math.min(18,a.vx)); a.y+=Math.max(-18,Math.min(18,a.vy)); }
        a.x=Math.max(8,Math.min(W-8,a.x)); a.y=Math.max(8,Math.min(H-8,a.y));
      }
      alpha *= 0.985;
    }
    function draw(){
      for (var i=0;i<edges.length;i++){ var e=edges[i], ln=lineEls[i];
        ln.setAttribute('x1',e.s.x); ln.setAttribute('y1',e.s.y);
        ln.setAttribute('x2',e.d.x); ln.setAttribute('y2',e.d.y); }
      for (i=0;i<nodes.length;i++){ nodeEls[i].setAttribute('cx',nodes[i].x); nodeEls[i].setAttribute('cy',nodes[i].y);
        if (labelEls[i]){ labelEls[i].setAttribute('x',nodes[i].x); labelEls[i].setAttribute('y',nodes[i].y - radius(nodes[i]) - 4); } }
    }
    var frames = 0;
    function tick(){ var steps = alpha>0.3?2:1; for (var s=0;s<steps;s++) step(); draw();
      frames++; if (alpha>0.02 && frames<600) requestAnimationFrame(tick); }
    requestAnimationFrame(tick);

    // --- Pan + zoom (pointer) ---
    var view = { x:0, y:0, k:1 };
    function applyView(){ gRoot.setAttribute('transform','translate('+view.x+','+view.y+') scale('+view.k+')'); }
    var dragging=false, last=null, pointers={};
    svgEl.addEventListener('pointerdown', function(e){ pointers[e.pointerId]={x:e.clientX,y:e.clientY};
      dragging=true; last={x:e.clientX,y:e.clientY}; svgEl.setPointerCapture(e.pointerId); });
    svgEl.addEventListener('pointermove', function(e){ if(!dragging) return;
      if (Object.keys(pointers).length>=2){ // pinch
        var ids=Object.keys(pointers); var p1=pointers[ids[0]], p2=pointers[ids[1]];
        var prev=Math.hypot(p1.x-p2.x,p1.y-p2.y); pointers[e.pointerId]={x:e.clientX,y:e.clientY};
        p1=pointers[ids[0]]; p2=pointers[ids[1]]; var now=Math.hypot(p1.x-p2.x,p1.y-p2.y);
        if(prev>0){ view.k=Math.max(0.3,Math.min(3, view.k*(now/prev))); applyView(); }
        return;
      }
      pointers[e.pointerId]={x:e.clientX,y:e.clientY};
      view.x += e.clientX-last.x; view.y += e.clientY-last.y; last={x:e.clientX,y:e.clientY}; applyView(); hideTip();
    });
    function up(e){ dragging=false; delete pointers[e.pointerId]; }
    svgEl.addEventListener('pointerup', up); svgEl.addEventListener('pointercancel', up);
    svgEl.addEventListener('wheel', function(e){ e.preventDefault();
      var f = e.deltaY<0?1.1:0.9; view.k=Math.max(0.3,Math.min(3,view.k*f)); applyView(); }, { passive:false });
    el('gReset').addEventListener('click', function(){ view={x:0,y:0,k:1}; applyView(); });
  }

  // ---- shared bits ----
  function bindTipTargets(scope){
    scope.querySelectorAll('[data-tt]').forEach(function(n){
      n.addEventListener('pointerenter', function(ev){ showTip(ev.clientX, ev.clientY, n.getAttribute('data-tt'), ''); });
      n.addEventListener('pointerleave', hideTip);
    });
  }
  function skeletonTiles(){ return '<div class="grid-tiles">'+
    '<div class="tile skel" style="height:78px"></div><div class="tile skel" style="height:78px"></div>'+
    '<div class="tile skel" style="height:78px"></div><div class="tile skel" style="height:78px"></div></div>'; }
  function skeletonCards(n){ var s=''; for(var i=0;i<n;i++) s+='<div class="listcard skel" style="height:72px;margin-bottom:11px"></div>'; return s; }
  function errorHtml(err){
    if (err && err.pending) return '<div class="empty">Your access is pending. Ask an admin to grant you a role, then reopen.</div>';
    return '<div class="empty">Could not load data.'+(err&&err.error?'<br><span class="muted">'+esc(err.error)+'</span>':'')+'</div>';
  }

  // ---- boot ----
  el('refresh').addEventListener('click', function(){
    if (tg && tg.HapticFeedback) { try { tg.HapticFeedback.impactOccurred('light'); } catch(e){} }
    cache = {}; loaded = {};
    var cur = document.querySelector('nav.tabs button[aria-selected="true"]').getAttribute('data-view');
    loaded[cur] = true; render[cur]();
    if (cur!=='overview') render.overview && (loaded.overview=true, render.overview());
  });
  document.body.addEventListener('click', hideTip);

  if (!initData) {
    el('view-overview').innerHTML = '<div class="empty">Open this page from inside Telegram (via the bot menu button).</div>';
    el('sub').textContent = 'Not in Telegram';
  } else {
    render.overview(); loaded.overview = true;
  }
})();
</script>
</body>
</html>`;

// Health Check & DB Migration
app.get('/', (c) => c.text('cHack Serverless Backend & Bot Running!'));
app.get('/api/db/migrate', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  try {
    // Add ip/country columns to runners table
    await c.env.DB.prepare("ALTER TABLE runners ADD COLUMN ip TEXT").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE runners ADD COLUMN country TEXT").run().catch(() => {});

    // Runner orchestration columns on scan_jobs (idempotent; each fails harmlessly if present)
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN region TEXT").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN priority INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN next_eligible_at INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN assigned_runner TEXT").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN started_at INTEGER").run().catch(() => {});
    await c.env.DB.prepare(
      "CREATE INDEX IF NOT EXISTS idx_scan_jobs_dispatch ON scan_jobs(status, priority DESC, created_at ASC)"
    ).run().catch(() => {});

    // Create new Reconner tables if not exist
    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
        company_id TEXT REFERENCES companies(id) ON DELETE CASCADE,
        tool TEXT NOT NULL,
        severity TEXT NOT NULL,
        vuln_type TEXT NOT NULL,
        title TEXT NOT NULL,
        url TEXT,
        description TEXT,
        evidence TEXT,
        poc TEXT,
        cve TEXT,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS endpoints (
        id TEXT PRIMARY KEY,
        domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        method TEXT DEFAULT 'GET',
        params TEXT DEFAULT '[]',
        status_code INTEGER,
        content_type TEXT,
        source TEXT,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
        rule_name TEXT NOT NULL,
        secret_type TEXT NOT NULL,
        match_snippet TEXT NOT NULL,
        file_url TEXT,
        severity TEXT NOT NULL DEFAULT 'high',
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS network_services (
        id TEXT PRIMARY KEY,
        domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        service TEXT,
        product TEXT,
        version TEXT,
        banner TEXT,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    // Task dependency graph (DAG) columns on scan_jobs
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN job_type TEXT").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN pipeline_id TEXT").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN parent_id TEXT").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN result TEXT DEFAULT '{}'").run().catch(() => {});
    await c.env.DB.prepare("ALTER TABLE scan_jobs ADD COLUMN depends_on TEXT DEFAULT '[]'").run().catch(() => {});
    await c.env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_scan_jobs_pipeline ON scan_jobs(pipeline_id)").run().catch(() => {});
    await c.env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status)").run().catch(() => {});

    // Trigger rules table (the dependency graph, stored as editable data)
    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS trigger_rules (
        id TEXT PRIMARY KEY,
        on_job_type TEXT NOT NULL,
        cond_key TEXT NOT NULL DEFAULT '',
        cond_op TEXT NOT NULL DEFAULT 'always',
        cond_value TEXT DEFAULT '',
        spawn_job_type TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});
    await c.env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_trigger_rules_on ON trigger_rules(on_job_type)").run().catch(() => {});

    // Seed the default dependency graph (idempotent)
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT OR IGNORE INTO trigger_rules (id, on_job_type, cond_key, cond_op, cond_value, spawn_job_type) VALUES (?,?,?,?,?,?)").bind('rule_sub_httpx',    'subdomain_enum', 'subdomains', 'gt',       '0',   'httpx'),
      c.env.DB.prepare("INSERT OR IGNORE INTO trigger_rules (id, on_job_type, cond_key, cond_op, cond_value, spawn_job_type) VALUES (?,?,?,?,?,?)").bind('rule_httpx_naabu',  'httpx',          'live_hosts', 'gt',       '0',   'naabu'),
      c.env.DB.prepare("INSERT OR IGNORE INTO trigger_rules (id, on_job_type, cond_key, cond_op, cond_value, spawn_job_type) VALUES (?,?,?,?,?,?)").bind('rule_httpx_katana', 'httpx',          'live_hosts', 'gt',       '0',   'katana'),
      c.env.DB.prepare("INSERT OR IGNORE INTO trigger_rules (id, on_job_type, cond_key, cond_op, cond_value, spawn_job_type) VALUES (?,?,?,?,?,?)").bind('rule_naabu_fp',     'naabu',          'open_ports', 'contains', '443', 'httpx_fingerprint'),
      c.env.DB.prepare("INSERT OR IGNORE INTO trigger_rules (id, on_job_type, cond_key, cond_op, cond_value, spawn_job_type) VALUES (?,?,?,?,?,?)").bind('rule_katana_nuclei','katana',         'endpoints',  'gt',       '0',   'nuclei'),
    ]);

    // Continuous attack-surface monitoring: recurring scan schedules
    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS monitors (
        id TEXT PRIMARY KEY,
        owner_chat_id INTEGER NOT NULL,
        target_type TEXT NOT NULL DEFAULT 'domain',
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL DEFAULT 'infogather',
        runner TEXT NOT NULL DEFAULT 'default',
        interval_minutes INTEGER NOT NULL DEFAULT 1440,
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run_at TEXT,
        next_run_at TEXT,
        last_job_id TEXT,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});
    await c.env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_monitors_due ON monitors(enabled, next_run_at)").run().catch(() => {});
    await c.env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_monitors_owner ON monitors(owner_chat_id)").run().catch(() => {});

    // Team workflows: roles, tokens, campaigns, groups, templates, playbooks.
    // users.role is unified with the Telegram RBAC model (pending/viewer/
    // operator/admin + ADMIN_IDS superadmin); API-token auth ranks unknown
    // roles lowest, so this stays fail-closed.
    await c.env.DB.prepare("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'pending'").run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS api_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL DEFAULT 'member',
        revoked INTEGER NOT NULL DEFAULT 0,
        last_used_at TEXT,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});
    await c.env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)").run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE,
        owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
        kind TEXT NOT NULL DEFAULT 'engagement',
        status TEXT NOT NULL DEFAULT 'prospect',
        authorized INTEGER NOT NULL DEFAULT 0,
        scope TEXT DEFAULT '{}',
        description TEXT,
        data TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS campaign_members (
        campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL DEFAULT 'member',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        PRIMARY KEY (campaign_id, user_id)
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS target_groups (
        id TEXT PRIMARY KEY,
        campaign_id TEXT REFERENCES campaigns(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        visibility TEXT NOT NULL DEFAULT 'team',
        description TEXT,
        data TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS target_group_members (
        group_id TEXT NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
        domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
        added_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        PRIMARY KEY (group_id, domain_id)
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS job_templates (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE,
        owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        visibility TEXT NOT NULL DEFAULT 'team',
        command_template TEXT NOT NULL,
        phases TEXT DEFAULT '[]',
        default_flags TEXT DEFAULT '{}',
        runner TEXT DEFAULT 'default',
        description TEXT,
        data TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS playbooks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE,
        campaign_id TEXT REFERENCES campaigns(id) ON DELETE SET NULL,
        owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        visibility TEXT NOT NULL DEFAULT 'team',
        description TEXT,
        data TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS playbook_steps (
        id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
        step_order INTEGER NOT NULL,
        template_id TEXT REFERENCES job_templates(id) ON DELETE SET NULL,
        phase TEXT,
        params TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE (playbook_id, step_order)
      )
    `).run().catch(() => {});

    await c.env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS target_playbooks (
        id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
        domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
        group_id TEXT REFERENCES target_groups(id) ON DELETE CASCADE,
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      )
    `).run().catch(() => {});

    return c.text("D1 Database Migrations applied successfully!");
  } catch (e) {
    return c.text("Migration failed: " + e.message, 500);
  }
});

app.post('/api/db/reset', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  // Destructive: wipes every table. Require an explicit confirmation field in
  // addition to the bearer token, so a leaked token alone can't trivially wipe
  // the central database by accident or replay.
  let body = {};
  try { body = await c.req.json(); } catch { /* no body */ }
  if (body.confirm !== 'WIPE') {
    return c.json({ success: false, error: "Refused: send {\"confirm\":\"WIPE\"} to confirm full database reset." }, 400);
  }
  try {
    const tables = [
      "target_playbooks",
      "playbook_steps",
      "playbooks",
      "job_templates",
      "target_group_members",
      "target_groups",
      "campaign_members",
      "campaigns",
      "api_tokens",
      "findings",
      "secrets",
      "network_services",
      "endpoints",
      "people",
      "domains",
      "companies",
      "scan_jobs",
      "runners",
      "sessions",
      "users"
    ];
    const statements = tables.map(t => c.env.DB.prepare(`DELETE FROM ${t}`));
    await c.env.DB.batch(statements);
    return c.json({ success: true, message: "Cloudflare D1 database wiped successfully." });
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500);
  }
});

// GraphQL Endpoint
app.post('/graphql', async (c) => {
  return yoga.handle(c.req.raw, { env: c.env });
});
app.get('/graphql', async (c) => {
  return yoga.handle(c.req.raw, { env: c.env });
});

// Telegram Bot Webhook
app.post('/webhook', async (c) => {
  // Verify the secret token Telegram echoes back (set via setWebhook's
  // secret_token). Enforced only when TELEGRAM_WEBHOOK_SECRET is configured,
  // so existing deployments keep working until they set it.
  const webhookSecret = c.env.TELEGRAM_WEBHOOK_SECRET;
  if (webhookSecret) {
    const presented = c.req.header('X-Telegram-Bot-Api-Secret-Token') || '';
    if (!safeEqual(presented, webhookSecret)) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
  }
  const bot = getBot(c.env);

  // Ensure the command list is cleared and the menu button opens the Mini App.
  // Runs once per isolate (and retries on failure); does not block the update.
  if (!botConfigured) {
    botConfigured = true;
    c.executionCtx.waitUntil(
      configureBotUI(c.env, bot).catch((err) => {
        botConfigured = false;
        console.error('configureBotUI failed:', err.message);
      })
    );
  }

  bot.use((ctx, next) => {
    ctx.executionCtx = c.executionCtx;
    return next();
  });
  return await webhookCallback(bot, 'hono')(c);
});

// Telegram Mini App: static shell + authorized data API.
app.get('/app', (c) => c.html(MINIAPP_HTML));
app.get('/app/api/summary', async (c) => {
  const authz = await authorizeMiniApp(c);
  if (!authz.ok) {
    return c.json({ error: authz.pending ? 'pending' : 'unauthorized' }, 401);
  }
  try {
    const stats = await collectDashboardStats(c.env);
    return c.json({
      ok: true,
      viewer: { username: authz.actor.username, role: authz.actor.role },
      stats,
      generatedAt: Date.now(),
    });
  } catch (err) {
    return c.json({ error: 'internal', detail: err.message }, 500);
  }
});

// Companies view: per-company asset/associate counts + severity breakdown.
app.get('/app/api/companies', async (c) => {
  const authz = await authorizeMiniApp(c);
  if (!authz.ok) return c.json({ error: authz.pending ? 'pending' : 'unauthorized' }, 401);
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT c.id, c.name, c.slug, " +
      " (SELECT count(*) FROM domains d WHERE d.company_id=c.id) AS domains, " +
      " (SELECT count(*) FROM people p WHERE p.company_id=c.id) AS people, " +
      " count(f.id) AS findings, " +
      " sum(CASE WHEN lower(f.severity)='critical' THEN 1 ELSE 0 END) AS crit, " +
      " sum(CASE WHEN lower(f.severity)='high' THEN 1 ELSE 0 END) AS high, " +
      " sum(CASE WHEN lower(f.severity)='medium' THEN 1 ELSE 0 END) AS med, " +
      " sum(CASE WHEN lower(f.severity)='low' THEN 1 ELSE 0 END) AS low, " +
      " sum(CASE WHEN lower(f.severity)='info' THEN 1 ELSE 0 END) AS info " +
      "FROM companies c LEFT JOIN findings f ON f.company_id=c.id " +
      "GROUP BY c.id ORDER BY findings DESC, domains DESC, c.name LIMIT 200"
    ).all();
    return c.json({ ok: true, companies: results || [] });
  } catch (err) { return c.json({ error: 'internal', detail: err.message }, 500); }
});

// People view: associates with their company + light OSINT summary (from data).
app.get('/app/api/people', async (c) => {
  const authz = await authorizeMiniApp(c);
  if (!authz.ok) return c.json({ error: authz.pending ? 'pending' : 'unauthorized' }, 401);
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT p.id, p.given_name, p.family_name, p.emails, p.data, " +
      " c.id AS company_id, c.name AS company " +
      "FROM people p LEFT JOIN companies c ON p.company_id=c.id " +
      "ORDER BY p.created_at DESC LIMIT 300"
    ).all();
    const people = (results || []).map((p) => {
      let emails = [], osint = {};
      try { emails = JSON.parse(p.emails || '[]'); } catch { emails = []; }
      try { const d = JSON.parse(p.data || '{}'); osint = d.osint || d || {}; } catch { osint = {}; }
      const acc = Array.isArray(osint.accounts) ? osint.accounts.length : (osint.accounts || 0);
      const br = Array.isArray(osint.breaches) ? osint.breaches.length : (osint.breaches || 0);
      return {
        id: p.id,
        name: [p.given_name, p.family_name].filter(Boolean).join(' ') || '(unnamed)',
        company: p.company || null, company_id: p.company_id || null,
        emails: emails.length, accounts: Number(acc) || 0, breaches: Number(br) || 0,
      };
    });
    return c.json({ ok: true, people });
  } catch (err) { return c.json({ error: 'internal', detail: err.message }, 500); }
});

// Map view: connection graph of companies -> their assets (domains) + associates
// (people). Node types map to categorical slots 1-3; company size encodes findings.
app.get('/app/api/graph', async (c) => {
  const authz = await authorizeMiniApp(c);
  if (!authz.ok) return c.json({ error: authz.pending ? 'pending' : 'unauthorized' }, 401);
  try {
    const comp = (await c.env.DB.prepare(
      "SELECT c.id, c.name, count(f.id) AS findings FROM companies c " +
      "LEFT JOIN findings f ON f.company_id=c.id GROUP BY c.id ORDER BY findings DESC LIMIT 60"
    ).all()).results || [];
    const compIds = new Set(comp.map((x) => x.id));
    const doms = (await c.env.DB.prepare(
      "SELECT id, company_id, host FROM domains WHERE company_id IS NOT NULL ORDER BY company_id LIMIT 400"
    ).all()).results || [];
    const ppl = (await c.env.DB.prepare(
      "SELECT id, company_id, given_name, family_name FROM people WHERE company_id IS NOT NULL ORDER BY company_id LIMIT 300"
    ).all()).results || [];

    const nodes = [], links = [];
    for (const x of comp) nodes.push({ id: 'c:' + x.id, t: 'company', label: x.name || '(company)', v: x.findings || 0 });
    for (const d of doms) {
      if (!compIds.has(d.company_id)) continue;
      nodes.push({ id: 'd:' + d.id, t: 'domain', label: d.host || '(host)' });
      links.push({ s: 'c:' + d.company_id, d: 'd:' + d.id });
    }
    for (const p of ppl) {
      if (!compIds.has(p.company_id)) continue;
      const nm = [p.given_name, p.family_name].filter(Boolean).join(' ') || '(person)';
      nodes.push({ id: 'p:' + p.id, t: 'person', label: nm });
      links.push({ s: 'c:' + p.company_id, d: 'p:' + p.id });
    }
    return c.json({ ok: true, nodes, links });
  } catch (err) { return c.json({ error: 'internal', detail: err.message }, 500); }
});

// Runner APIs (Background Scan Executer)

// --- Orchestration tunables -------------------------------------------------
// A runner that has not sent next-job/heartbeat within this window is treated as
// offline; its in-flight jobs become eligible for reclaim.
const RUNNER_STALE_SECS = 180;
// Hard ceiling on a single run regardless of heartbeats — a wedged job past this
// lease is reclaimed so it cannot occupy a slot forever. Set well above a normal
// full-pipeline scan so a legitimately long job is never double-dispatched.
const JOB_LEASE_SECS = 21600; // 6h
// Retry backoff: delay = min(cap, base * 2^attempts), plus up to +50% jitter.
const RETRY_BASE_SECS = 30;
const RETRY_CAP_SECS = 1800;

// Seconds to wait before a failed/reclaimed job may run again, with jitter so a
// fleet-wide outage doesn't requeue everything into one synchronized wave.
function retryDelaySecs(attempts) {
  const base = Math.min(RETRY_CAP_SECS, RETRY_BASE_SECS * Math.pow(2, Math.max(0, attempts)));
  return Math.round(base + Math.random() * base * 0.5);
}

// Requeue (or fail) jobs stranded on a runner that has gone offline or blown its
// lease. Runs opportunistically on each poll; cheap and idempotent.
async function reclaimStaleJobs(env, nowSecs) {
  const runnerCutoff = nowSecs - RUNNER_STALE_SECS;
  const leaseCutoff = nowSecs - JOB_LEASE_SECS;
  // Condition: the job is running, but its holder is unknown/offline, or the
  // lease has expired outright.
  const staleWhere =
    "status = 'running' AND (" +
    "  (started_at IS NOT NULL AND started_at < ?) " +
    "  OR assigned_runner IS NULL " +
    "  OR assigned_runner NOT IN (SELECT name FROM runners WHERE last_seen >= ?)" +
    ")";

  // Out of attempts -> give up.
  await env.DB.prepare(
    "UPDATE scan_jobs SET status = 'failed', assigned_runner = NULL, " +
    "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') " +
    "WHERE attempts >= max_attempts AND " + staleWhere
  ).bind(leaseCutoff, runnerCutoff).run().catch(() => {});

  // Still has attempts left -> back to the queue after a jittered backoff.
  await env.DB.prepare(
    "UPDATE scan_jobs SET status = 'pending', assigned_runner = NULL, started_at = NULL, " +
    "next_eligible_at = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') " +
    "WHERE attempts < max_attempts AND " + staleWhere
  ).bind(nowSecs + retryDelaySecs(1), leaseCutoff, runnerCutoff).run().catch(() => {});
}

app.get('/api/runner/next-job', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const runner = c.req.query('runner') || 'default';
  // How many jobs this runner may hold at once (auto-balance: don't pile work on
  // a node that is already busy — let idle nodes pick it up instead).
  const slots = Math.max(1, parseInt(c.req.query('slots') || '1', 10) || 1);

  // Register runner heartbeat (Unix timestamp in seconds)
  const nowSecs = Math.floor(Date.now() / 1000);
  const ip = c.req.header('CF-Connecting-IP') || c.req.header('x-real-ip') || '127.0.0.1';
  const country = c.req.header('cf-ipcountry') || 'US';

  await c.env.DB.prepare(
    "INSERT INTO runners (name, ip, country, last_seen) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(name) DO UPDATE SET ip = excluded.ip, country = excluded.country, last_seen = excluded.last_seen"
  ).bind(runner, ip, country, nowSecs).run();

  // Recover work stranded on offline runners before handing out anything new.
  // (reclaimStaleJobs requeues jobs whose runner went silent, up to max_attempts,
  // then fails them — a failed job never spawns DAG children.)
  await reclaimStaleJobs(c.env, nowSecs);

  // Load balancing: refuse a new job if this runner is already at capacity.
  const load = await c.env.DB.prepare(
    "SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'running' AND assigned_runner = ?"
  ).bind(runner).first();
  if (load && load.n >= slots) {
    return c.json({ job: null, reason: 'at_capacity' });
  }

  // Pick the next dispatchable job:
  //  - eligible now (retry backoff elapsed),
  //  - addressed to this runner or unpinned,
  //  - region matches this runner's country or is unpinned,
  //  - ordered by priority, then region-locality, then age.
  const job = await c.env.DB.prepare(
    "SELECT * FROM scan_jobs WHERE status = 'pending' " +
    "AND next_eligible_at <= ? " +
    "AND (runner = ? OR runner = 'default' OR runner IS NULL OR runner = '') " +
    "AND (region IS NULL OR region = '' OR region = ?) " +
    "ORDER BY priority DESC, CASE WHEN region = ? THEN 0 ELSE 1 END, created_at ASC LIMIT 1"
  ).bind(nowSecs, runner, country, country).first();

  if (!job) {
    return c.json({ job: null });
  }

  // Atomic claim: only succeeds if the row is still pending, so two runners
  // racing for the same job cannot both win it.
  const claim = await c.env.DB.prepare(
    "UPDATE scan_jobs SET status = 'running', assigned_runner = ?, started_at = ?, " +
    "attempts = attempts + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') " +
    "WHERE id = ? AND status = 'pending'"
  ).bind(runner, nowSecs, job.id).run();

  if (!claim.meta || claim.meta.changes !== 1) {
    // Lost the race; the runner will poll again shortly.
    return c.json({ job: null, reason: 'contended' });
  }

  job.status = 'running';
  job.assigned_runner = runner;
  job.attempts = (job.attempts || 0) + 1;

  // Audit the dispatch so execution is traceable to the requester and runner.
  await auditLog(c.env, {
    actor_user_id: job.requested_by || null,
    actor_number_id: job.requested_by_number_id || 0,
    actor_label: `runner:${runner}`,
    source: 'daemon', action: 'job.dispatch', target_type: 'job', target: job.domain,
    company_id: job.company_id || null,
    detail: { job_id: job.id, runner, command: job.command },
  });

  return c.json({ job });
});

// Lightweight keepalive so a runner busy on a long job stays "online" and its
// in-flight work is not wrongly reclaimed. Also refreshes the running job's lease.
app.get('/api/runner/heartbeat', async (c) => {
  const runner = c.req.query('runner') || 'default';
  const nowSecs = Math.floor(Date.now() / 1000);
  const ip = c.req.header('CF-Connecting-IP') || c.req.header('x-real-ip') || '127.0.0.1';
  const country = c.req.header('cf-ipcountry') || 'US';
  await c.env.DB.prepare(
    "INSERT INTO runners (name, ip, country, last_seen) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(name) DO UPDATE SET ip = excluded.ip, country = excluded.country, last_seen = excluded.last_seen"
  ).bind(runner, ip, country, nowSecs).run();
  return c.json({ success: true, ts: nowSecs });
});

app.post('/api/runner/log', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const { id, log } = await c.req.json();
  await c.env.DB.prepare(
    "UPDATE scan_jobs SET stdout = stdout || ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
  ).bind(log, id).run();
  return c.json({ success: true });
});

// ==========================================================================
// Task dependency graph (DAG) orchestration
// ==========================================================================

// Evaluate one trigger rule's condition against a parent job's result JSON.
function evalCondition(rule, result) {
  const op = rule.cond_op || 'always';
  if (op === 'always') return true;
  const actual = result ? result[rule.cond_key] : undefined;
  const val = rule.cond_value;
  switch (op) {
    case 'exists':
      return actual !== undefined && actual !== null;
    case 'eq':
      return String(actual) === String(val);
    case 'gt':
      return Number(actual) > Number(val);
    case 'gte':
      return Number(actual) >= Number(val);
    case 'contains':
      if (Array.isArray(actual)) return actual.map(String).includes(String(val));
      return String(actual ?? '').includes(String(val));
    default:
      return false;
  }
}

// Build the runner command for a spawned child phase, carrying the sender id
// through from the parent so Telegram notifications still route correctly.
function buildPhaseCommand(jobType, domain, parentCommand) {
  const m = (parentCommand || '').match(/--sender-id\s+(\S+)/);
  const senderPart = m ? ` --sender-id ${m[1]}` : '';
  return `--phase ${jobType} ${domain}${senderPart}`;
}

// When a job completes, enqueue the child jobs its result triggers.
// Dedupe by (pipeline_id, job_type): every phase runs at most once per
// pipeline, which also makes cycles in the rule set impossible.
async function spawnTriggeredJobs(env, job) {
  let result = {};
  try { result = JSON.parse(job.result || '{}'); } catch { result = {}; }

  const { results: rules } = await env.DB.prepare(
    "SELECT * FROM trigger_rules WHERE on_job_type = ? AND enabled = 1"
  ).bind(job.job_type || '').all();

  for (const rule of rules || []) {
    if (!evalCondition(rule, result)) continue;

    // Skip if this phase already exists in the pipeline (dedupe / anti-cycle).
    if (job.pipeline_id) {
      const existing = await env.DB.prepare(
        "SELECT id FROM scan_jobs WHERE pipeline_id = ? AND job_type = ? LIMIT 1"
      ).bind(job.pipeline_id, rule.spawn_job_type).first();
      if (existing) continue;
    }

    const childId = crypto.randomUUID();
    const command = buildPhaseCommand(rule.spawn_job_type, job.domain, job.command);
    await env.DB.prepare(
      "INSERT INTO scan_jobs (id, command, domain, runner, status, job_type, pipeline_id, parent_id) " +
      "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)"
    ).bind(
      childId, command, job.domain, job.runner || 'default',
      rule.spawn_job_type, job.pipeline_id || job.id, job.id
    ).run();
  }
}

// Release any 'blocked' jobs in the pipeline whose dependencies are all done.
async function releaseBlockedJobs(env, pipelineId) {
  if (!pipelineId) return;
  const { results: blocked } = await env.DB.prepare(
    "SELECT * FROM scan_jobs WHERE pipeline_id = ? AND status = 'blocked'"
  ).bind(pipelineId).all();

  for (const b of blocked || []) {
    let deps = [];
    try { deps = JSON.parse(b.depends_on || '[]'); } catch { deps = []; }
    if (!deps.length) { // no deps recorded -> nothing holds it
      await env.DB.prepare("UPDATE scan_jobs SET status = 'pending', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(b.id).run();
      continue;
    }
    const placeholders = deps.map(() => '?').join(',');
    const { results: unmet } = await env.DB.prepare(
      `SELECT id FROM scan_jobs WHERE id IN (${placeholders}) AND status != 'completed'`
    ).bind(...deps).all();
    if (!unmet || unmet.length === 0) {
      await env.DB.prepare("UPDATE scan_jobs SET status = 'pending', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").bind(b.id).run();
    }
  }
}

app.post('/api/runner/status', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const { id, status, result } = await c.req.json();
  const nowSecs = Math.floor(Date.now() / 1000);
  const resultJson = (result === undefined || result === null)
    ? null
    : (typeof result === 'string' ? result : JSON.stringify(result));

  // On failure, retry with jittered backoff until max_attempts is exhausted.
  // A requeued job is not terminal, so it does not drive the dependency graph.
  if (status === 'failed') {
    const job = await c.env.DB.prepare(
      "SELECT attempts, max_attempts FROM scan_jobs WHERE id = ?"
    ).bind(id).first();

    if (job && job.attempts < job.max_attempts) {
      await c.env.DB.prepare(
        "UPDATE scan_jobs SET status = 'pending', assigned_runner = NULL, started_at = NULL, " +
        "next_eligible_at = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
      ).bind(nowSecs + retryDelaySecs(job.attempts), id).run();
      return c.json({ success: true, requeued: true, attempts: job.attempts, max_attempts: job.max_attempts });
    }
  }

  // Terminal state (completed, or failed with no attempts left): record the
  // result, release the lease.
  await c.env.DB.prepare(
    "UPDATE scan_jobs SET status = ?, result = COALESCE(?, result), assigned_runner = NULL, " +
    "updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
  ).bind(status, resultJson, id).run();

  // On successful completion, drive the dependency graph forward.
  if (status === 'completed') {
    const job = await c.env.DB.prepare("SELECT * FROM scan_jobs WHERE id = ?").bind(id).first();
    if (job) {
      try {
        await spawnTriggeredJobs(c.env, job);
        await releaseBlockedJobs(c.env, job.pipeline_id);
      } catch (e) {
        // Orchestration failure must not fail the status update itself.
        console.error("DAG orchestration error:", e.message);
      }
    }
  }
  return c.json({ success: true });
});

// --------------------------------------------------------------------------
// Autonomous onboarding (Phase 1): runner <-> backend program exchange.
// RUNNER_TOKEN-authed. The runner fetches a candidate's raw scope, parses it
// locally (scope_parser.py), and pushes the parsed proposal back; the backend
// raises the Telegram approval gate. scope.txt is only ever written on the
// runner, on approval (--onboard-apply-remote).
// --------------------------------------------------------------------------
app.get('/api/runner/program', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const id = c.req.query('id');
  if (!id) return c.json({ error: 'id required' }, 400);
  const row = await c.env.DB.prepare("SELECT * FROM bb_programs WHERE id = ?").bind(id).first();
  if (!row) return c.json({ error: 'not found' }, 404);
  return c.json({ program: row });
});

app.post('/api/runner/program/parsed', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const body = await c.req.json().catch(() => ({}));
  const { id } = body;
  if (!id || !body.scope_parsed) return c.json({ error: 'id and scope_parsed required' }, 400);
  const prog = await c.env.DB.prepare("SELECT * FROM bb_programs WHERE id = ?").bind(id).first();
  if (!prog) return c.json({ error: 'not found' }, 404);

  const parsed = typeof body.scope_parsed === 'string' ? JSON.parse(body.scope_parsed) : body.scope_parsed;
  const flags = body.roe_flags || parsed.roe_flags || [];
  await c.env.DB.prepare(
    "UPDATE bb_programs SET scope_parsed=?, roe_flags=?, status='pending_approval', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?"
  ).bind(JSON.stringify(parsed), JSON.stringify(flags), id).run();

  const emit = parsed.scope_txt_lines || [];
  const wild = parsed.wildcards || [];
  const chatId = prog.created_by;

  const apprId = crypto.randomUUID();
  await c.env.DB.prepare(
    "INSERT INTO pending_approvals (id, kind, program_id, payload, chat_id, status) VALUES (?, 'onboard', ?, ?, ?, 'pending')"
  ).bind(apprId, id, JSON.stringify({ emit, wild, flags }), chatId || null).run();

  if (chatId) {
    try {
      const bot = getBot(c.env);
      const esc = (s) => String(s).replace(/[&<>]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[ch]));
      const emitList = emit.length ? emit.map(h => `  • <code>${esc(h)}</code>`).join("\n") : "  (none — nothing emittable)";
      const wildLine = wild.length ? `\n⚠️ <b>${wild.length} wildcard(s)</b> NOT added (need manual scope): ${wild.map(w => `<code>*.${esc(w)}</code>`).join(", ")}` : "";
      const roeLine = flags.length ? `\n🚩 <b>RoE flags:</b> ${flags.map(f => `<code>${esc(f)}</code>`).join(", ")}` : "";
      const text =
        `🪪 <b>Approve onboarding:</b> <code>${esc(prog.handle || prog.name || id)}</code> [${esc(prog.platform)}]\n\n` +
        `<b>${emit.length} host(s)/range(s) to add to scope.txt:</b>\n${emitList}` + wildLine + roeLine +
        `\n\nApprove to write these to <code>scope.txt</code> on the runner and begin monitoring.`;
      await bot.api.sendMessage(chatId, text, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[
          { text: "✅ Approve", callback_data: `onboard_ok:${id}` },
          { text: "🚫 Skip", callback_data: `onboard_no:${id}` },
        ]] },
      });
    } catch (e) {
      console.error("onboard gate send failed:", e.message);
    }
  }
  return c.json({ success: true, pending_approval: apprId });
});

app.post('/api/runner/program/applied', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const body = await c.req.json().catch(() => ({}));
  const { id, added } = body;
  if (!id) return c.json({ error: 'id required' }, 400);
  await c.env.DB.prepare(
    "UPDATE bb_programs SET status='active', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?"
  ).bind(id).run();
  const prog = await c.env.DB.prepare("SELECT created_by, handle, name FROM bb_programs WHERE id = ?").bind(id).first();
  if (prog && prog.created_by) {
    try {
      const bot = getBot(c.env);
      const n = Array.isArray(added) ? added.length : 0;
      await bot.api.sendMessage(prog.created_by,
        `✅ <b>Onboarded</b> <code>${String(prog.handle || prog.name || id).replace(/[&<>]/g, '')}</code> — ${n} host(s) now in scope.txt. Continuous monitoring will pick them up.`,
        { parse_mode: "HTML" });
    } catch (e) { console.error("applied notify failed:", e.message); }
  }
  return c.json({ success: true });
});

// Phase 3 auto-discovery: the runner pushes discovered candidate programs here.
// New ones (deduped by platform+handle) are stored as 'new' and the operator is
// sent a single summary to review with /programs. Nothing is scanned or scoped
// automatically — discovery only surfaces programs; onboarding stays human-gated.
app.post('/api/runner/discovered', async (c) => {
  if (!runnerTokenOk(c)) return c.json({ error: 'unauthorized' }, 401);
  const body = await c.req.json().catch(() => ({}));
  const cands = Array.isArray(body.candidates) ? body.candidates : [];
  const adminRaw = String((c.env.ADMIN_IDS || '').split(',')[0] || '').trim();
  const adminId = /^\d+$/.test(adminRaw) ? Number(adminRaw) : null;
  const newNames = [];
  for (const cand of cands) {
    if (!cand || !cand.platform || !cand.handle) continue;
    const id = crypto.randomUUID();
    let res;
    try {
      res = await c.env.DB.prepare(
        "INSERT OR IGNORE INTO bb_programs (id, platform, handle, name, url, scope_raw, roe_raw, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)"
      ).bind(id, String(cand.platform), String(cand.handle), String(cand.name || cand.handle), String(cand.url || ''), String(cand.scope_raw || ''), String(cand.roe_raw || ''), adminId).run();
    } catch (e) { continue; }
    if (res && res.meta && res.meta.changes > 0) newNames.push(`${cand.name || cand.handle} [${cand.platform}]`);
  }
  if (newNames.length && adminId) {
    try {
      const bot = getBot(c.env);
      const esc = (s) => String(s).replace(/[&<>]/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[ch]));
      const list = newNames.slice(0, 20).map(n => `  • ${esc(n)}`).join("\n");
      const more = newNames.length > 20 ? `\n  …and ${newNames.length - 20} more` : "";
      await bot.api.sendMessage(adminId,
        `🛰️ <b>Discovery:</b> ${newNames.length} new bug-bounty program(s) found:\n${list}${more}\n\nReview and onboard with <code>/programs</code>.`,
        { parse_mode: "HTML" });
    } catch (e) { console.error('discovery notify:', e.message); }
  }
  return c.json({ success: true, new: newNames.length, total: cands.length });
});

// Start a new pipeline: seed a single root job and let triggers cascade.
app.post('/api/pipeline/start', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const domain = body.domain;
  if (!domain) return c.json({ success: false, error: "domain required" }, 400);
  const runner = body.runner || 'default';
  const rootType = body.job_type || 'subdomain_enum';
  const senderId = body.sender_id;

  const id = crypto.randomUUID();
  const command = buildPhaseCommand(rootType, domain, senderId ? `--sender-id ${senderId}` : '');
  // pipeline_id = the root job's own id, so every descendant shares it.
  await c.env.DB.prepare(
    "INSERT INTO scan_jobs (id, command, domain, runner, status, job_type, pipeline_id) " +
    "VALUES (?, ?, ?, ?, 'pending', ?, ?)"
  ).bind(id, command, domain, runner, rootType, id).run();

  return c.json({ success: true, pipeline_id: id, job_id: id });
});

// Inspect every job in a pipeline (for rendering the DAG + per-node status).
app.get('/api/pipeline/:id', async (c) => {
  const pipelineId = c.req.param('id');
  const { results } = await c.env.DB.prepare(
    "SELECT id, job_type, parent_id, status, result, created_at, updated_at FROM scan_jobs WHERE pipeline_id = ? ORDER BY created_at ASC"
  ).bind(pipelineId).all();
  return c.json({ pipeline_id: pipelineId, jobs: results || [] });
});

// List / create trigger rules (the editable dependency graph).
app.get('/api/rules', async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM trigger_rules ORDER BY on_job_type, spawn_job_type"
  ).all();
  return c.json({ rules: results || [] });
});

app.post('/api/rules', async (c) => {
  const b = await c.req.json().catch(() => ({}));
  if (!b.on_job_type || !b.spawn_job_type) {
    return c.json({ success: false, error: "on_job_type and spawn_job_type required" }, 400);
  }
  const id = b.id || crypto.randomUUID();
  await c.env.DB.prepare(
    "INSERT INTO trigger_rules (id, on_job_type, cond_key, cond_op, cond_value, spawn_job_type, enabled) " +
    "VALUES (?, ?, ?, ?, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET on_job_type=excluded.on_job_type, cond_key=excluded.cond_key, " +
    "cond_op=excluded.cond_op, cond_value=excluded.cond_value, spawn_job_type=excluded.spawn_job_type, enabled=excluded.enabled"
  ).bind(
    id, b.on_job_type, b.cond_key || '', b.cond_op || 'always',
    b.cond_value != null ? String(b.cond_value) : '', b.spawn_job_type,
    b.enabled === false ? 0 : 1
  ).run();
  return c.json({ success: true, id });
});

app.delete('/api/rules/:id', async (c) => {
  await c.env.DB.prepare("DELETE FROM trigger_rules WHERE id = ?").bind(c.req.param('id')).run();
  return c.json({ success: true });
});

// ----------------------------------------------------
// Scheduled (Cron Trigger): dispatch due monitors
// ----------------------------------------------------
// Runs on the Worker cron schedule (see wrangler.json). Finds monitors whose
// next_run_at has elapsed, enqueues scan jobs into the shared runner queue,
// and rolls their schedule forward. Company monitors fan out to one scan per
// distinct registrable domain known for that company.
const scheduled = async (event, env, ctx) => {
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();

  // Phase 3 auto-discovery: at most once every DISCOVERY_INTERVAL_MS, enqueue a
  // runner job that pulls public programs from the platform feeds. The runner
  // posts new candidates to /api/runner/discovered; nothing is scoped until the
  // operator reviews them via /programs. Self-throttled with a sessions key so
  // it fires on only one of the (frequent) cron ticks.
  try {
    const DISCOVERY_INTERVAL_MS = Number(env.DISCOVERY_INTERVAL_MS) || 6 * 60 * 60 * 1000;
    const row = await env.DB.prepare("SELECT value FROM sessions WHERE key = 'last_discovery_at'").first();
    const last = row ? Number(row.value) || 0 : 0;
    if (nowMs - last >= DISCOVERY_INTERVAL_MS) {
      const jobId = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO scan_jobs (id, command, domain, runner, status, job_type, source) VALUES (?, '--discover --sender-id 0', '', 'default', 'pending', 'discover', 'daemon')"
      ).bind(jobId).run();
      await env.DB.prepare(
        "INSERT INTO sessions (key, value) VALUES ('last_discovery_at', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
      ).bind(String(nowMs)).run();
    }
  } catch (err) {
    console.error("scheduled: discovery dispatch failed:", err.message);
  }

  let due = [];
  try {
    const res = await env.DB.prepare(
      "SELECT * FROM monitors WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?) ORDER BY next_run_at ASC LIMIT 50"
    ).bind(nowIso).all();
    due = res.results || [];
  } catch (err) {
    console.error("scheduled: monitor query failed:", err.message);
    return;
  }

  if (due.length === 0) return;

  let bot = null;
  try { bot = getBot(env); } catch { /* alerts are best-effort */ }

  for (const m of due) {
    try {
      // Resolve the concrete scan targets for this monitor.
      let targets = [m.target];
      if (m.target_type === "company") {
        try {
          const dres = await env.DB.prepare(
            "SELECT d.host FROM domains d " +
            "JOIN companies c ON d.company_id = c.id " +
            "WHERE lower(c.slug) = lower(?) OR lower(c.name) = lower(?)"
          ).bind(m.target, m.target).all();
          const bases = new Set();
          for (const row of (dres.results || [])) {
            if (row.host) bases.add(registrableBase(row.host));
          }
          if (bases.size > 0) targets = Array.from(bases);
        } catch (err) {
          console.error("scheduled: company expansion failed:", err.message);
        }
      }

      const jobIds = [];
      for (const t of targets) {
        const command = buildMonitorCommand(m, t);
        const jobId = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO scan_jobs (id, command, domain, runner, status) VALUES (?, ?, ?, ?, 'pending')"
        ).bind(jobId, command, t, m.runner || "default").run();
        jobIds.push(jobId);
      }

      const nextIso = new Date(nowMs + (m.interval_minutes || 1440) * 60000).toISOString();
      await env.DB.prepare(
        "UPDATE monitors SET last_run_at = ?, next_run_at = ?, last_job_id = ? WHERE id = ?"
      ).bind(nowIso, nextIso, jobIds[0] || null, m.id).run();

      if (bot) {
        const scope = targets.length > 1 ? ` (${targets.length} domains)` : "";
        await bot.api.sendMessage(
          m.owner_chat_id,
          `🛰️ <b>Scheduled scan queued</b> for <code>${escapeHtml(m.target)}</code>${scope}\n` +
          `• Scan: <code>${m.scan_type}</code>\n` +
          `• Next run: ${nextIso.replace("T", " ").slice(0, 16)}`,
          { parse_mode: "HTML" }
        ).catch(() => {});
      }
    } catch (err) {
      console.error(`scheduled: failed to dispatch monitor ${m.id}:`, err.message);
    }
  }
};

export default {
  fetch: app.fetch,
  scheduled,
};

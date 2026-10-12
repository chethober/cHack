import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { createYoga, createSchema } from 'graphql-yoga';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { GraphQLJSON } from 'graphql-type-json';
import { DateTimeResolver } from 'graphql-scalars';
import { Bot, webhookCallback } from 'grammy';
import { GraphQLScalarType, Kind } from 'graphql';

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

  type Query {
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
  graphqlEndpoint: '/graphql'
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

  return {
    inline_keyboard: [
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
      ],
      [
        { text: `⚙️ Runner (${runnerStatusText})`, callback_data: "change_runner" },
        { text: "⚠️ Reset DB", callback_data: "confirm_reset_db" }
      ]
    ]
  };
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

  // Admin access gate middleware
  bot.use(async (ctx, next) => {
    if (!ctx.from) return;
    const adminIdsStr = env.ADMIN_IDS || "";
    const adminIds = adminIdsStr.split(",").map(id => Number(id.trim())).filter(id => !isNaN(id));
    
    if (adminIds.length > 0 && !adminIds.includes(ctx.from.id)) {
      console.log(`Unauthorized access attempt by Telegram ID: ${ctx.from.id}`);
      return;
    }
    await next();
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

  // Queue scan helper
  const triggerScan = async (ctx, type, value, runner = 'default', opts = {}) => {
    const priority = Number.isFinite(opts.priority) ? opts.priority : 0;
    const region = opts.region || null;
    const userId = ctx.from?.id || 0;
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
    
    const id = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO scan_jobs (id, command, domain, runner, region, priority, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')"
    ).bind(id, command, value, runner, region, priority).run();
    return id;
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
    await ctx.reply("🛰️ <b>cHack C2 Control Center</b>\n\nWelcome back! Manage your targets, active reconnaissance jobs, vulnerability findings, and scanner runners below:", {
      parse_mode: "HTML",
      reply_markup: menuMarkup
    });
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
      keyboard.push([{ text: `👤 ${name}`, callback_data: `view_contact_${p.id}` }]);
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
    const res = await env.DB.prepare("DELETE FROM scan_jobs WHERE status IN ('completed', 'failed')").run();
    await ctx.reply(`🧹 Cleaned up finished/failed scan jobs from queue.`);
  });

  bot.command("newcompany", async (ctx) => {
    await registerUser(ctx);
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
    ctx.session.step = 'PERSON_INPUT';
    await ctx.reply("🔍 <b>Target: Person</b>\n\nSend me the person's phone number (<code>+1555...</code>), username (<code>@che...</code>), or name (e.g. <code>Cheth Ober</code>):", {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]]
      }
    });
  });

  bot.command("delcompany", async (ctx) => {
    const name = ctx.match?.trim();
    if (!name) {
      return await ctx.reply("❌ Usage: <code>/delcompany &lt;company name or slug&gt;</code>", { parse_mode: "HTML" });
    }
    const comp = await env.DB.prepare("SELECT * FROM companies WHERE lower(name) = lower(?) OR lower(slug) = lower(?)").bind(name, name).first();
    if (!comp) {
      return await ctx.reply(`❌ Company <code>${escapeHtml(name)}</code> not found.`, { parse_mode: "HTML" });
    }
    await env.DB.prepare("DELETE FROM companies WHERE id = ?").bind(comp.id).run();
    await ctx.reply(`🗑️ Company <code>${escapeHtml(comp.name)}</code> and all associated domains/findings deleted.`, { parse_mode: "HTML" });
  });

  bot.command("deldomain", async (ctx) => {
    const host = ctx.match?.trim()?.toLowerCase();
    if (!host) {
      return await ctx.reply("❌ Usage: <code>/deldomain &lt;host&gt;</code>", { parse_mode: "HTML" });
    }
    const dom = await env.DB.prepare("SELECT * FROM domains WHERE lower(host) = lower(?)").bind(host).first();
    if (!dom) {
      return await ctx.reply(`❌ Domain <code>${escapeHtml(host)}</code> not found.`, { parse_mode: "HTML" });
    }
    await env.DB.prepare("DELETE FROM domains WHERE id = ?").bind(dom.id).run();
    await ctx.reply(`🗑️ Domain <code>${escapeHtml(host)}</code> deleted.`, { parse_mode: "HTML" });
  });

  bot.command("delperson", async (ctx) => {
    const name = ctx.match?.trim();
    if (!name) {
      return await ctx.reply("❌ Usage: <code>/delperson &lt;first name&gt;</code>", { parse_mode: "HTML" });
    }
    const person = await env.DB.prepare("SELECT * FROM people WHERE lower(given_name) = lower(?) OR lower(given_name || ' ' || coalesce(family_name, '')) = lower(?)").bind(name, name).first();
    if (!person) {
      return await ctx.reply(`❌ Person <code>${escapeHtml(name)}</code> not found.`, { parse_mode: "HTML" });
    }
    await env.DB.prepare("DELETE FROM people WHERE id = ?").bind(person.id).run();
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
        `• <b>Notes:</b> ${escapeHtml(p.notes || 'None')}`
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

  bot.command("help", async (ctx) => {
    await ctx.reply(
      `📖 <b>cHack Bot Command & Management Guide</b>\n\n` +
      `<b>Navigation & Dashboard:</b>\n` +
      `• <code>/menu</code> or <code>/start</code> - Open interactive Main Menu\n` +
      `• <code>/dashboard</code> or <code>/stats</code> - System stats & asset counts\n` +
      `• <code>/resetdb</code> - Wipe & reset Cloudflare DB\n` +
      `• <code>/help</code> - Show this guide\n\n` +
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
      `• <code>/unmonitor &lt;id&gt;</code> - Remove a monitor`,
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
        keyboard.push([{ text: `👤 ${name}`, callback_data: `view_contact_${p.id}` }]);
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
        `• <b>Created At:</b> <code>${person.created_at}</code>`;

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
      try {
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
          "users"
        ];
        const statements = tables.map(t => env.DB.prepare(`DELETE FROM ${t}`));
        await env.DB.batch(statements);

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

app.use('*', cors());

// Health Check & DB Migration
app.get('/', (c) => c.text('cHack Serverless Backend & Bot Running!'));
app.get('/api/db/migrate', async (c) => {
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

    return c.text("D1 Database Migrations applied successfully!");
  } catch (e) {
    return c.text("Migration failed: " + e.message, 500);
  }
});

app.post('/api/db/reset', async (c) => {
  try {
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
  const bot = getBot(c.env);
  bot.use((ctx, next) => {
    ctx.executionCtx = c.executionCtx;
    return next();
  });
  return await webhookCallback(bot, 'hono')(c);
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

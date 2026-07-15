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
      const statements = [];
      for (const result of results) {
        const raw_url = result.url || '';
        // strip scheme
        const host = raw_url.replace(/^https?:\/\//, '');
        const patch = JSON.stringify({
          title: result.title || '',
          webserver: result.webserver || '',
          status_code: result.status_code || 0,
          headers: result.header || {},
          tech: result.tech || [],
          last_scan: new Date().toISOString()
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
    }
  },

  // Relationship resolvers
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



const createMainMenu = async (ctx, env) => {
  const currentRunner = ctx.session?.selected_runner || 'default';
  let runnerText = `⚙️ Runner: ${currentRunner}`;

  try {
    // Verify runner heartbeat status (active in last 60 seconds)
    const cutoff = Math.floor(Date.now() / 1000) - 60;
    const activeRunner = await env.DB.prepare(
      "SELECT name, ip, country FROM runners WHERE name = ? AND last_seen >= ?"
    ).bind(currentRunner, cutoff).first();

    if (activeRunner) {
      const flag = getFlagEmoji(activeRunner.country);
      runnerText = `⚙️ Runner: ${flag} ${activeRunner.ip}`;
    } else {
      // Attempt to query last known IP/country even if offline
      const lastKnown = await env.DB.prepare(
        "SELECT ip, country FROM runners WHERE name = ?"
      ).bind(currentRunner).first();
      if (lastKnown) {
        const flag = getFlagEmoji(lastKnown.country);
        runnerText = `⚠️ Offline: ${flag} ${lastKnown.ip}`;
      } else {
        runnerText = `⚠️ Runner Offline: ${currentRunner}`;
      }
    }
  } catch (err) {
    console.error("D1 error in createMainMenu:", err.message);
    runnerText = `⚙️ Runner: ${currentRunner}`;
  }

  return {
    inline_keyboard: [
      [
        { text: "🔎Person", callback_data: "target_person" },
        { text: "🔎Company", callback_data: "target_company" },
        { text: "⚙️Runners", callback_data: "change_runner" }
      ],
      [
        { text: "👥People", callback_data: "view_contacts" },
        { text: "🎯Targets", callback_data: "view_targets" },
        { text: "📜Scans", callback_data: "view_new_domains" }
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
    
    // Read session with catch
    try {
      const row = await env.DB.prepare("SELECT value FROM sessions WHERE key = ?").bind(key).first();
      ctx.session = row ? JSON.parse(row.value) : {};
    } catch (err) {
      console.error("D1 session read error:", err.message);
      ctx.session = {};
    }
    
    await next();
    
    // Write session with catch
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
    
    if (!adminIds.includes(ctx.from.id)) {
      console.log(`Unauthorized access attempt by Telegram ID: ${ctx.from.id}`);
      return; // Stop execution
    }
    await next();
  });

  // Helper: auto-register user on first bot interaction
  const registerUser = async (ctx) => {
    if (ctx.session.user_registered) return;
    
    const user = ctx.from;
    if (user) {
      const username = user.username || `user_${user.id}`;
      try {
        // Check if user exists in D1
        const existing = await env.DB.prepare("SELECT id FROM users WHERE number_id = ?").bind(user.id).first();
        if (!existing) {
          const uuid = crypto.randomUUID();
          await env.DB.prepare(
            `INSERT INTO users (id, username, number_id, first_name, last_name)
             VALUES (?, ?, ?, ?, ?)`
          ).bind(uuid, username, user.id, user.first_name || '', user.last_name || '').run();
        }
        ctx.session.user_registered = true;
      } catch (err) {
        console.error("D1 user registration error:", err.message);
        // Do not block execution
        ctx.session.user_registered = true;
      }
    }
  };

  // Helper: format domains list
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
    return `<b><a href="http://${host}">${host}</a></b> ${statusStr} ~ <i>${title}</i> | <code>${tech}</code>`;
  };

  // Queue scan helper
  const triggerScan = async (ctx, type, value, runner = 'default') => {
    const userId = ctx.from?.id || 0;
    let command = "";
    if (type === 'domain') {
      command = `-d ${value} --sender-id ${userId}`;
    } else if (type === 'person') {
      command = `-p "${value}" --sender-id ${userId}`;
    } else if (type === 'company') {
      // Check if value is domain
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value);
      if (isDomain) {
        command = `-d ${value} --sender-id ${userId}`;
      } else {
        command = `-c "${value}" --sender-id ${userId}`;
      }
    }
    
    // Insert into scan_jobs queue
    const id = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO scan_jobs (id, command, domain, runner, status) VALUES (?, ?, ?, ?, 'pending')"
    ).bind(id, command, value, runner).run();

    // Local runner triggers scan queue via polling
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
    
    // Add Refresh & Cancel options
    keyboard.push([
      { text: "🔄 Refresh", callback_data: "change_runner" },
      { text: "🔙 Cancel", callback_data: "cancel" }
    ]);
    return { inline_keyboard: keyboard };
  };

  const safeEditMessageText = async (ctx, text, options) => {
    try {
      return await ctx.editMessageText(text, options);
    } catch (err) {
      const desc = err && (err.description || (err.error && err.error.description) || err.message || "");
      if (desc && String(desc).toLowerCase().includes("message is not modified")) {
        console.log("Ignored: Message is not modified error.");
      } else {
        throw err;
      }
    }
  };

  // Bot commands
  bot.command("start", async (ctx) => {
    await registerUser(ctx);
    if (!ctx.session.selected_runner) {
      ctx.session.selected_runner = 'default';
    }
    ctx.session.step = 'MAIN_MENU';
    const menuMarkup = await createMainMenu(ctx, env);
    await ctx.reply("hey, good 2 c u back", {
      parse_mode: "HTML",
      reply_markup: menuMarkup
    });
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
    await ctx.reply("🔍 <b>Target: Person</b>\n\nsend me the person's phone number (<code>+1555...</code>), username (<code>@che...</code>), or name (e.g. <code>Cheth Ober</code>):", {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]]
      }
    });
  });

  // Query bot command handlers
  bot.command("getuser", async (ctx) => {
    const username = ctx.match?.trim();
    if (!username) {
      return await ctx.reply("❌ Usage: <code>/getuser &lt;username&gt;</code>", { parse_mode: "HTML" });
    }
    const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
    if (!user) {
      return await ctx.reply(`❌ User <code>${username}</code> not found.`, { parse_mode: "HTML" });
    }
    await ctx.reply(
      `👤 <b>User: ${user.username}</b>\n\n` +
      `• <b>ID:</b> <code>${user.id}</code>\n` +
      `• <b>Telegram ID:</b> <code>${user.number_id || 'N/A'}</code>\n` +
      `• <b>First Name:</b> ${user.first_name || 'N/A'}\n` +
      `• <b>Last Name:</b> ${user.last_name || 'N/A'}\n` +
      `• <b>Created At:</b> <code>${user.created_at}</code>`,
      { parse_mode: "HTML" }
    );
  });

  bot.command("getcompany", async (ctx) => {
    const company_name = ctx.match?.trim();
    if (!company_name) {
      return await ctx.reply("❌ Usage: <code>/getcompany &lt;company name&gt;</code>", { parse_mode: "HTML" });
    }
    const company = await env.DB.prepare("SELECT * FROM companies WHERE name = ?").bind(company_name).first();
    if (!company) {
      return await ctx.reply(`❌ Company <code>${company_name}</code> not found.`, { parse_mode: "HTML" });
    }
    const { results: domains } = await env.DB.prepare("SELECT host FROM domains WHERE company_id = ?").bind(company.id).all();
    const { results: people } = await env.DB.prepare("SELECT given_name, family_name FROM people WHERE company_id = ?").bind(company.id).all();
    
    const comp_data = parseJson(company.data);
    const phase = comp_data.phase || 'N/A';
    const domains_list = domains.length ? domains.map(d => `• <code>${d.host}</code>`).join('\n') : "None";
    const people_list = people.length ? people.map(p => `• ${p.given_name} ${p.family_name || ''}`).join('\n') : "None";

    await ctx.reply(
      `🏢 <b>Company: ${company.name}</b>\n\n` +
      `• <b>ID:</b> <code>${company.id}</code>\n` +
      `• <b>Slug:</b> <code>${company.slug || 'N/A'}</code>\n` +
      `• <b>Description:</b> ${company.description || 'N/A'}\n` +
      `• <b>Phase:</b> <code>${phase}</code>\n` +
      `• <b>Created At:</b> <code>${company.created_at}</code>\n\n` +
      `🌐 <b>Domains (${domains.length}):</b>\n${domains_list}\n\n` +
      `👤 <b>People (${people.length}):</b>\n${people_list}`,
      { parse_mode: "HTML" }
    );
  });

  bot.command("getdomain", async (ctx) => {
    const host = ctx.match?.trim()?.toLowerCase();
    if (!host) {
      return await ctx.reply("❌ Usage: <code>/getdomain &lt;host&gt;</code>", { parse_mode: "HTML" });
    }
    const domain = await env.DB.prepare("SELECT * FROM domains WHERE lower(host) = lower(?)").bind(host).first();
    if (!domain) {
      return await ctx.reply(`❌ Domain <code>${host}</code> not found.`, { parse_mode: "HTML" });
    }
    const company = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(domain.company_id).first();
    const domData = parseJson(domain.data);
    const title = domData.title || 'N/A';
    const webserver = domData.webserver || 'N/A';
    const status_code = domData.status_code || 'N/A';
    const tech = (domData.tech || []).join(', ') || 'N/A';

    await ctx.reply(
      `🌐 <b>Domain: ${domain.host}</b>\n\n` +
      `• <b>ID:</b> <code>${domain.id}</code>\n` +
      `• <b>Company:</b> ${company ? company.name : 'N/A'}\n` +
      `• <b>Canonical URL:</b> ${domain.canonical_url || 'N/A'}\n` +
      `• <b>Status Code:</b> <code>${status_code}</code>\n` +
      `• <b>Title:</b> ${title}\n` +
      `• <b>Web Server:</b> ${webserver}\n` +
      `• <b>Tech:</b> ${tech}\n` +
      `• <b>Created At:</b> <code>${domain.created_at}</code>`,
      { parse_mode: "HTML" }
    );
  });

  bot.command(["getpeople", "getperson"], async (ctx) => {
    const args = ctx.match?.trim()?.split(/\s+/) || [];
    if (args.length === 0 || args[0] === '') {
      return await ctx.reply("❌ Usage: <code>/getpeople &lt;first name&gt; [last name]</code>", { parse_mode: "HTML" });
    }
    const givenName = args[0];
    const familyName = args[1] || null;

    let query = "SELECT * FROM people WHERE given_name = ?";
    const binds = [givenName];
    if (familyName) {
      query += " AND family_name = ?";
      binds.push(familyName);
    }
    
    const { results: people } = await env.DB.prepare(query).bind(...binds).all();
    if (!people.length) {
      const name_str = familyName ? `${givenName} ${familyName}` : givenName;
      return await ctx.reply(`❌ Person <code>${name_str}</code> not found.`, { parse_mode: "HTML" });
    }

    const msgs = [];
    for (const p of people.slice(0, 5)) {
      const emails = parseJson(p.emails).join(', ') || "None";
      const phones = parseJson(p.phones).join(', ') || "None";
      const comp = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(p.company_id).first();
      
      msgs.push(
        `👤 <b>Person: ${p.given_name} ${p.family_name || ''}</b>\n` +
        `• <b>ID:</b> <code>${p.id}</code>\n` +
        `• <b>Company:</b> ${comp ? comp.name : 'N/A'}\n` +
        `• <b>Emails:</b> ${emails}\n` +
        `• <b>Phones:</b> ${phones}\n` +
        `• <b>Notes:</b> ${p.notes || 'None'}`
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
      return `• <code>${d.host}</code> - <i>${title}</i>`;
    });

    await ctx.reply(
      `🔍 <b>Domains with Status Code ${statusCode}:</b>\n` +
      lines.join('\n'),
      { parse_mode: "HTML" }
    );
  });

  // Bot callback queries
  bot.on("callback_query:data", async (ctx) => {
    const data = ctx.callbackQuery.data;
    await registerUser(ctx);

    if (data === "target_domain") {
      ctx.session.step = 'DOMAIN_INPUT';
      await ctx.editMessageText("🌐 <b>Target: Domain</b>\n\nsend me the domain name (e.g. <code>example.com</code>):", {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]]
        }
      });
    } else if (data === "target_person") {
      ctx.session.step = 'PERSON_INPUT';
      await ctx.editMessageText("🔍 <b>Target: Person</b>\n\nsend me the person's phone number (<code>+1555...</code>), username (<code>@che...</code>), or name (e.g. <code>Cheth Ober</code>):", {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]]
        }
      });
    } else if (data === "target_company") {
      ctx.session.step = 'COMPANY_INPUT';
      await ctx.editMessageText("🏢 <b>Target: Company / Domain</b>\n\nPlease send me the company name or domain (e.g. <code>CHTH Corp</code> or <code>chth.xyz</code>):", {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🔙 Cancel", callback_data: "cancel" }]]
        }
      });
    } else if (data === "cancel") {
      ctx.session.step = 'MAIN_MENU';
      const menuMarkup = await createMainMenu(ctx, env);
      await safeEditMessageText(ctx, "❌ Action cancelled. Select a target type:", {
        reply_markup: menuMarkup
      });
    } else if (data === "change_runner") {
      ctx.session.step = 'RUNNER_SELECTION';
      // Instantly show checking status to prevent lag or hang visual
      await safeEditMessageText(
        ctx,
        "⚙️ <b>Select Active Runner</b>\n\n🔄 Checking for active scanner runners...",
        { parse_mode: "HTML" }
      ).catch(() => {});

      const runnerMarkup = await createRunnerKeyboard();
      await safeEditMessageText(
        ctx,
        "⚙️ <b>Runners Management</b>\n\n" +
        "Choose a runner to select it as active or manage (rename/remove) it (🟢 indicates active in the last 60 seconds, 🔴 indicates inactive):",
        {
          parse_mode: "HTML",
          reply_markup: runnerMarkup
        }
      );
    } else if (data === "no_active_runners") {
      await ctx.answerCallbackQuery({
        text: "No runners are currently connected. Please start runner.js on your VPS.",
        show_alert: true
      });
    } else if (data.startsWith("select_runner:")) {
      const runner = data.split(":").pop();
      ctx.session.selected_runner = runner;
      ctx.session.step = 'MAIN_MENU';
      await ctx.editMessageText(`✅ Active runner updated to: <code>${runner}</code>`, {
        parse_mode: "HTML"
      });
      const menuMarkup = await createMainMenu(ctx, env);
      await ctx.reply("Select a target type to scan:", {
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
            text: "Runner not found. It might have been deleted.",
            show_alert: true
          });
        }

        const cutoff = Math.floor(Date.now() / 1000) - 60;
        const isActive = runner.last_seen >= cutoff;
        const statusStr = isActive ? "🟢 <b>Active</b>" : "🔴 <b>Inactive</b>";
        const lastSeenStr = new Date(runner.last_seen * 1000).toISOString().replace('T', ' ').substring(0, 19) + " UTC";
        const flag = getFlagEmoji(runner.country);

        const detailsText = 
          `⚙️ <b>Manage Runner:</b> <code>${runner.name}</code>\n\n` +
          `• <b>Status:</b> ${statusStr}\n` +
          `• <b>IP Address:</b> <code>${runner.ip || 'N/A'}</code>\n` +
          `• <b>Country:</b> ${flag} ${runner.country || 'N/A'}\n` +
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
        await ctx.answerCallbackQuery({
          text: `Error loading runner details: ${err.message}`,
          show_alert: true
        });
      }
    } else if (data.startsWith("prep_rename:")) {
      const runnerName = data.split(":").pop();
      ctx.session.step = 'RENAME_RUNNER';
      ctx.session.target_runner = runnerName;
      await safeEditMessageText(ctx, `✏️ <b>Rename Runner:</b> <code>${runnerName}</code>\n\nPlease send the new name for this runner:`, {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[{ text: "🔙 Cancel", callback_data: `manage_runner:${runnerName}` }]]
        }
      });
    } else if (data.startsWith("remove_runner:")) {
      const runnerName = data.split(":").pop();
      try {
        await env.DB.prepare("DELETE FROM runners WHERE name = ?").bind(runnerName).run();
        
        // If the removed runner was the currently selected runner, fallback to default
        if (ctx.session.selected_runner === runnerName) {
          ctx.session.selected_runner = 'default';
        }

        await safeEditMessageText(ctx, `❌ Runner <code>${runnerName}</code> has been removed from the database.`, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Go to Runners", callback_data: "change_runner" }]]
          }
        });
      } catch (err) {
        console.error("D1 error in remove_runner:", err.message);
        await ctx.answerCallbackQuery({
          text: `Error removing runner: ${err.message}`,
          show_alert: true
        });
      }
    } else if (data === "view_new_domains") {
      const { results: jobs } = await env.DB.prepare(
        "SELECT * FROM scan_jobs WHERE status IN ('pending', 'running') ORDER BY created_at DESC"
      ).all();
      
      if (!jobs.length) {
        return await safeEditMessageText(
          ctx,
          "📜 <b>Ongoing Scans</b>\n\nNo ongoing scan jobs at the moment.", 
          {
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "🔄 Refresh", callback_data: "view_new_domains" }],
                [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
              ]
            }
          }
        );
      }
      
      const lines = [];
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
            } catch (e) {}
          }
        }
        
        const runner = job.runner || 'default';
        lines.push(`🎯 <b>${job.domain}</b> | ⚙️ <code>${runner}</code> | ⏳ Phase: <code>${phase}</code>`);
      }
      
      await safeEditMessageText(
        ctx,
        `📜 <b>Ongoing Scans</b>\n\n${lines.join('\n')}`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "🔄 Refresh", callback_data: "view_new_domains" }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    } else if (data.startsWith("new_domains_page_")) {
      const page = Number(data.split("_").pop());
      const offset = page * 10;
      const { results: domains } = await env.DB.prepare("SELECT * FROM domains ORDER BY created_at DESC LIMIT 10 OFFSET ?").bind(offset).all();
      const lines = domains.map(d => formatDomainLine(d));
      
      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Previous", callback_data: `new_domains_page_${page - 1}` });
      if (domains.length === 10) navRow.push({ text: "Next ➡️", callback_data: `new_domains_page_${page + 1}` });

      await ctx.editMessageText(
        `🆕 <b>Newly Discovered Domains</b> (Page ${page + 1})\n\n${lines.join('\n')}`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              navRow,
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    } else if (data === "view_targets") {
      const { results: companies } = await env.DB.prepare("SELECT * FROM companies LIMIT 10").all();
      if (!companies.length) {
        return await ctx.editMessageText("🎯 <b>Targets</b>\n\nNo companies found in the database.", {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Main Menu", callback_data: "main_menu" }]]
          }
        });
      }
      const keyboard = companies.map(c => [{ text: c.name, callback_data: `view_company_domains_${c.id}_0` }]);
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);
      await ctx.editMessageText("🎯 <b>Targets (Companies)</b>\n\nSelect a company to view its domains:", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_company_domains_")) {
      const parts = data.split("_");
      const company_id = parts[3];
      const page = Number(parts[4] || 0);
      const offset = page * 10;

      const comp = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(company_id).first();
      const { results: domains } = await env.DB.prepare("SELECT * FROM domains WHERE company_id = ? ORDER BY created_at DESC LIMIT 10 OFFSET ?").bind(company_id, offset).all();
      
      const comp_name = comp ? comp.name : "Unknown";
      const lines = domains.map(d => formatDomainLine(d));

      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Previous", callback_data: `view_company_domains_${company_id}_${page - 1}` });
      if (domains.length === 10) navRow.push({ text: "Next ➡️", callback_data: `view_company_domains_${company_id}_${page + 1}` });

      const keyboard = [
        navRow,
        [{ text: "🔙 Back to Targets", callback_data: "view_targets" }],
        [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
      ].filter(r => r.length > 0);

      await ctx.editMessageText(
        `🏢 <b>Company: ${comp_name} Domains</b> (Page ${page + 1})\n\n${lines.join('\n') || 'None'}`,
        {
          parse_mode: "HTML",
          reply_markup: { inline_keyboard: keyboard }
        }
      );
    } else if (data === "view_contacts") {
      const { results: people } = await env.DB.prepare("SELECT * FROM people LIMIT 10").all();
      if (!people.length) {
        return await ctx.editMessageText("👤 <b>Contacts</b>\n\nNo contacts found in the database.", {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Main Menu", callback_data: "main_menu" }]]
          }
        });
      }
      const keyboard = people.map(p => {
        const name = `${p.given_name} ${p.family_name || ''}`.trim();
        return [{ text: name, callback_data: `view_contact_${p.id}` }];
      });
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);
      await ctx.editMessageText("👤 <b>Contacts</b>\n\nSelect a contact to view details:", {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("contacts_page_")) {
      const page = Number(data.split("_").pop());
      const offset = page * 10;
      const { results: people } = await env.DB.prepare("SELECT * FROM people LIMIT 10 OFFSET ?").bind(offset).all();
      
      const keyboard = people.map(p => {
        const name = `${p.given_name} ${p.family_name || ''}`.trim();
        return [{ text: name, callback_data: `view_contact_${p.id}` }];
      });
      
      const navRow = [];
      if (page > 0) navRow.push({ text: "◀️ Previous", callback_data: `contacts_page_${page - 1}` });
      if (people.length === 10) navRow.push({ text: "Next ➡️", callback_data: `contacts_page_${page + 1}` });

      keyboard.push(navRow);
      keyboard.push([{ text: "🔙 Main Menu", callback_data: "main_menu" }]);

      await ctx.editMessageText(`👤 <b>Contacts</b> (Page ${page + 1})\n\nSelect a contact to view details:`, {
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: keyboard }
      });
    } else if (data.startsWith("view_contact_")) {
      const contactId = data.split("_").pop();
      const person = await env.DB.prepare("SELECT * FROM people WHERE id = ?").bind(contactId).first();
      if (!person) {
        return await ctx.editMessageText("❌ Contact not found.", {
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Back to Contacts", callback_data: "view_contacts" }]]
          }
        });
      }
      
      const emails = parseJson(person.emails).join(', ') || "None";
      const phones = parseJson(person.phones).join(', ') || "None";
      const company = await env.DB.prepare("SELECT name FROM companies WHERE id = ?").bind(person.company_id).first();
      const name = `${person.given_name} ${person.family_name || ''}`.trim();
      const username = parseJson(person.data).username || "No Username";

      await ctx.editMessageText(
        `👤 <b>Contact: ${name}</b>\n\n` +
        `• <b>ID:</b> <code>${person.id}</code>\n` +
        `• <b>Username:</b> <code>${username}</code>\n` +
        `• <b>Company:</b> ${company ? company.name : 'N/A'}\n` +
        `• <b>Emails:</b> ${emails}\n` +
        `• <b>Phones:</b> ${phones}\n` +
        `• <b>Notes:</b> ${person.notes || 'None'}\n` +
        `• <b>Created At:</b> <code>${person.created_at}</code>`,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "🔙 Back to Contacts", callback_data: "view_contacts" }],
              [{ text: "🔙 Main Menu", callback_data: "main_menu" }]
            ]
          }
        }
      );
    } else if (data === "main_menu") {
      ctx.session.step = 'MAIN_MENU';
      const menuMarkup = await createMainMenu(ctx, env);
      await safeEditMessageText(ctx, "hey, good 2 c u back", {
        reply_markup: menuMarkup
      });
    }
  });

  // Bot incoming message routing based on state steps
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
      // Validate domain
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(text);
      if (!isDomain) {
        return await ctx.reply("❌ Invalid domain format. Try again or type /start to reset.");
      }
      await triggerScan(ctx, 'domain', text, runner);
      ctx.session.step = 'MAIN_MENU';
      await ctx.reply(
        `🚀 <b>Starting recon scan...</b>\n\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Command:</b> <code>./cHack.sh -d ${text}</code>`,
        {
          parse_mode: "HTML"
        }
      );
      const menuMarkup = await createMainMenu(ctx, env);
      await ctx.reply("Select another target type to scan:", { reply_markup: menuMarkup });
    } 
    else if (step === 'PERSON_INPUT') {
      await triggerScan(ctx, 'person', text, runner);
      ctx.session.step = 'MAIN_MENU';
      await ctx.reply(
        `🚀 <b>Starting recon scan...</b>\n\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Command:</b> <code>./cHack.sh -p "${text}"</code>`,
        {
          parse_mode: "HTML"
        }
      );
      const menuMarkup = await createMainMenu(ctx, env);
      await ctx.reply("Select another target type to scan:", { reply_markup: menuMarkup });
    } 
    else if (step === 'COMPANY_INPUT') {
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(text);
      const targetType = isDomain ? 'domain' : 'company';
      await triggerScan(ctx, targetType, text, runner);
      ctx.session.step = 'MAIN_MENU';
      
      let cmdStr = isDomain ? `./cHack.sh -d ${text}` : `./cHack.sh -c "${text}"`;
      await ctx.reply(
        `🚀 <b>Starting recon scan...</b>\n\n` +
        `• <b>Runner:</b> <code>${runner}</code>\n` +
        `• <b>Command:</b> <code>${cmdStr}</code>`,
        {
          parse_mode: "HTML"
        }
      );
      const menuMarkup = await createMainMenu(ctx, env);
      await ctx.reply("Select another target type to scan:", { reply_markup: menuMarkup });
    } 
    else if (step === 'RENAME_RUNNER') {
      const oldRunnerName = ctx.session.target_runner;
      const newRunnerName = text.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9_-]/g, '');
      if (!newRunnerName || newRunnerName.length < 2) {
        return await ctx.reply("❌ Invalid runner name. Use alphanumeric characters, dashes, and underscores. Please send a new name:");
      }

      try {
        // Check if name already exists
        const existing = await env.DB.prepare("SELECT name FROM runners WHERE name = ?").bind(newRunnerName).first();
        if (existing) {
          return await ctx.reply(`❌ A runner named <code>${newRunnerName}</code> already exists. Please send a different name:`, { parse_mode: "HTML" });
        }

        // Update runner name in runners table
        await env.DB.prepare("UPDATE runners SET name = ?, last_seen = strftime('%s', 'now') WHERE name = ?").bind(newRunnerName, oldRunnerName).run();

        // Update pending/running jobs for this runner
        await env.DB.prepare("UPDATE scan_jobs SET runner = ? WHERE runner = ?").bind(newRunnerName, oldRunnerName).run();

        // If the renamed runner was the selected one in the user's session, update it
        if (ctx.session.selected_runner === oldRunnerName) {
          ctx.session.selected_runner = newRunnerName;
        }

        ctx.session.step = 'MAIN_MENU';
        ctx.session.target_runner = null;

        await ctx.reply(`✅ Runner <code>${oldRunnerName}</code> successfully renamed to <code>${newRunnerName}</code>.`, {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "🔙 Go to Runners", callback_data: "change_runner" }]]
          }
        });
      } catch (err) {
        console.error("D1 error in rename runner:", err.message);
        await ctx.reply(`❌ Database error while renaming runner: ${err.message}`);
      }
    } 
    else {
      // Default: check if domain
      const isDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(text);
      if (isDomain) {
        await triggerScan(ctx, 'domain', text, runner);
        await ctx.reply(
          `🚀 <b>Starting recon scan for domain...</b>\n\n` +
          `• <b>Runner:</b> <code>${runner}</code>\n` +
          `• <b>Command:</b> <code>./cHack.sh -d ${text}</code>`,
          {
            parse_mode: "HTML"
          }
        );
        const menuMarkup = await createMainMenu(ctx, env);
        await ctx.reply("Select another target type to scan:", { reply_markup: menuMarkup });
      } else {
        const menuMarkup = await createMainMenu(ctx, env);
        await ctx.reply("To start a scan, select a target type from the menu or send a valid domain:", { reply_markup: menuMarkup });
      }
    }
  });

  // Global grammY error catcher
  bot.catch((err) => {
    const ctx = err.ctx;
    console.error(`Error while handling update ${ctx.update.update_id}:`);
    const e = err.error;
    // Suppress "message is not modified" Bad Requests to keep bot UI responsive
    if (e && e.description && e.description.includes("message is not modified")) {
      console.log("Ignored Telegram API Error: Message is not modified");
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
    return c.text("D1 Database Migrations applied successfully!");
  } catch (e) {
    return c.text("Migration failed: " + e.message, 500);
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
app.get('/api/runner/next-job', async (c) => {
  const runner = c.req.query('runner') || 'default';
  
  // Register runner heartbeat (Unix timestamp in seconds)
  const nowSecs = Math.floor(Date.now() / 1000);
  const ip = c.req.header('CF-Connecting-IP') || c.req.header('x-real-ip') || '127.0.0.1';
  const country = c.req.header('cf-ipcountry') || 'US';

  await c.env.DB.prepare(
    "INSERT INTO runners (name, ip, country, last_seen) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(name) DO UPDATE SET ip = excluded.ip, country = excluded.country, last_seen = excluded.last_seen"
  ).bind(runner, ip, country, nowSecs).run();

  // Fetch next pending job for this runner or default
  const job = await c.env.DB.prepare(
    "SELECT * FROM scan_jobs WHERE status = 'pending' AND (runner = ? OR runner = 'default' OR runner IS NULL OR runner = '') ORDER BY created_at ASC LIMIT 1"
  ).bind(runner).first();
  
  if (!job) {
    return c.json({ job: null });
  }

  // Mark as running
  await c.env.DB.prepare(
    "UPDATE scan_jobs SET status = 'running', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
  ).bind(job.id).run();

  return c.json({ job });
});

app.post('/api/runner/log', async (c) => {
  const { id, log } = await c.req.json();
  await c.env.DB.prepare(
    "UPDATE scan_jobs SET stdout = stdout || ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
  ).bind(log, id).run();
  return c.json({ success: true });
});

app.post('/api/runner/status', async (c) => {
  const { id, status } = await c.req.json();
  await c.env.DB.prepare(
    "UPDATE scan_jobs SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
  ).bind(status, id).run();
  return c.json({ success: true });
});

export default app;

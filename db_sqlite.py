import sys
import os
import re
import json
import sqlite3
import base64
import uuid
from datetime import datetime, timezone

DB_PATH = os.environ.get(
    "CHACK_DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "local.db")
)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "back", "schema.sql")
    if not os.path.exists(schema_path):
        print(f"Error: schema.sql not found at {schema_path}")
        return
    
    conn = get_db()
    cursor = conn.cursor()
    with open(schema_path, "r") as f:
        schema_sql = f.read()
    
    # Migrate FIRST: CREATE TABLE IF NOT EXISTS never alters an already-present
    # table, and schema.sql builds indexes on the new scan_jobs columns — those
    # CREATE INDEX statements would fail on a legacy table whose columns haven't
    # been backfilled yet. On a fresh DB the tables don't exist, so migrate_db
    # is a no-op and executescript creates everything (columns included).
    migrate_db(conn)

    cursor.executescript(schema_sql)

    # Idempotent upgrade of pre-existing local.db to the DAG schema.
    # CREATE TABLE IF NOT EXISTS above is a no-op on an existing table, so
    # the new columns must be added explicitly.
    for ddl in (
        "ALTER TABLE scan_jobs ADD COLUMN job_type TEXT",
        "ALTER TABLE scan_jobs ADD COLUMN pipeline_id TEXT",
        "ALTER TABLE scan_jobs ADD COLUMN parent_id TEXT",
        "ALTER TABLE scan_jobs ADD COLUMN result TEXT DEFAULT '{}'",
        "ALTER TABLE scan_jobs ADD COLUMN depends_on TEXT DEFAULT '[]'",
    ):
        try:
            cursor.execute(ddl)
        except sqlite3.OperationalError:
            pass  # column already present

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

def _columns(cursor, table):
    try:
        cursor.execute(f"PRAGMA table_info({table})")
        return {row[1] for row in cursor.fetchall()}
    except sqlite3.Error:
        return set()

def migrate_db(conn):
    """Idempotently add columns introduced after a DB was first created."""
    cursor = conn.cursor()
    additions = {
        "users": [("role", "TEXT DEFAULT 'pending'")],
        "scan_jobs": [
            ("requested_by", "TEXT"),
            ("requested_by_number_id", "INTEGER"),
            ("company_id", "TEXT"),
            ("source", "TEXT DEFAULT 'telegram'"),
            # Orchestration columns added after the original scan_jobs schema.
            # Without these, schema.sql's idx_scan_jobs_dispatch (which indexes
            # `priority`) fails on a legacy DB and aborts the whole executescript.
            ("region", "TEXT"),
            ("priority", "INTEGER NOT NULL DEFAULT 0"),
            ("attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("max_attempts", "INTEGER NOT NULL DEFAULT 3"),
            ("next_eligible_at", "INTEGER NOT NULL DEFAULT 0"),
            ("assigned_runner", "TEXT"),
            ("started_at", "INTEGER"),
            # DAG columns — also needed before executescript builds their indexes.
            ("job_type", "TEXT"),
            ("pipeline_id", "TEXT"),
            ("parent_id", "TEXT"),
            ("result", "TEXT DEFAULT '{}'"),
            ("depends_on", "TEXT DEFAULT '[]'"),
        ],
    }
    for table, cols in additions.items():
        existing = _columns(cursor, table)
        if not existing:
            continue  # table doesn't exist yet; executescript will have made it
        for name, decl in cols:
            if name not in existing:
                try:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                except sqlite3.Error as e:
                    print(f"migration warning ({table}.{name}): {e}")
    conn.commit()

def write_audit(action, actor_label=None, actor_number_id=0, source='cli',
                decision='allow', target_type=None, target=None, company_id=None,
                detail=None):
    """Append one row to the local audit_log. Best-effort; never raises."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO audit_log
                 (id, actor_user_id, actor_number_id, actor_label, source, action,
                  decision, target_type, target, company_id, detail)
               VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), int(actor_number_id or 0), actor_label, source, action,
             decision, target_type, target, company_id,
             json.dumps(detail or {})),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        # Audit failures must not break a scan.
        sys.stderr.write(f"audit write failed: {e}\n")

def save_job(job_file):
    try:
        with open(job_file, 'r') as f:
            job = json.load(f)
        os.remove(job_file)
    except Exception as e:
        print(f"Error reading/deleting job file: {e}")
        return
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if job exists
    cursor.execute("SELECT id FROM scan_jobs WHERE id = ?", (job['id'],))
    row = cursor.fetchone()
    
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
    
    if row:
        cursor.execute("""
            UPDATE scan_jobs
            SET command = ?, domain = ?, runner = ?, status = ?,
                job_type = ?, pipeline_id = ?, parent_id = ?, updated_at = ?
            WHERE id = ?
        """, (job['command'], job['domain'], job.get('runner', 'default'), job['status'],
              job.get('job_type'), job.get('pipeline_id'), job.get('parent_id'), now, job['id']))
    else:
        cursor.execute("""
            INSERT INTO scan_jobs (id, command, domain, runner, status, stdout,
                                   job_type, pipeline_id, parent_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (job['id'], job['command'], job['domain'], job.get('runner', 'default'), job['status'],
              job.get('stdout', ''), job.get('job_type'), job.get('pipeline_id'), job.get('parent_id'), now, now))
    
    conn.commit()
    conn.close()

def append_log(job_id, log_base64):
    try:
        log_chunk = base64.b64decode(log_base64).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error decoding log: {e}")
        return
    
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
    cursor.execute("""
        UPDATE scan_jobs
        SET stdout = COALESCE(stdout, '') || ?, updated_at = ?
        WHERE id = ?
    """, (log_chunk, now, job_id))
    conn.commit()
    conn.close()

def update_status(job_id, status, result=None):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
    if result:
        try:
            cursor.execute("""
                UPDATE scan_jobs
                SET status = ?, result = ?, updated_at = ?
                WHERE id = ?
            """, (status, result, now, job_id))
        except sqlite3.OperationalError:
            # 'result' column missing on a stale db; fall back to status only.
            cursor.execute("UPDATE scan_jobs SET status = ?, updated_at = ? WHERE id = ?", (status, now, job_id))
    else:
        cursor.execute("""
            UPDATE scan_jobs
            SET status = ?, updated_at = ?
            WHERE id = ?
        """, (status, now, job_id))
    conn.commit()
    conn.close()

def update_domain_data(conn, host, patch):
    cursor = conn.cursor()
    cursor.execute("SELECT data FROM domains WHERE lower(host) = lower(?)", (host,))
    row = cursor.fetchone()
    if row:
        try:
            current_data = json.loads(row[0] or '{}')
        except:
            current_data = {}
        
        # Merge dictionaries
        for k, v in patch.items():
            if isinstance(v, dict) and isinstance(current_data.get(k), dict):
                current_data[k].update(v)
            else:
                current_data[k] = v
        
        cursor.execute(
            "UPDATE domains SET data = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE lower(host) = lower(?)",
            (json.dumps(current_data), host)
        )

def execute_graphql(in_file, res_file):
    try:
        with open(in_file, 'r') as f:
            payload = json.load(f)
        with open(res_file, 'r') as f:
            response = json.load(f)
        os.remove(in_file)
        os.remove(res_file)
    except Exception as e:
        print(f"Error loading GraphQL files: {e}")
        return

    if 'errors' in response:
        print("GraphQL response has errors, skipping local SQLite write.")
        return

    query = payload.get('query', '')
    variables = payload.get('variables', {}) or {}
    data = response.get('data', {}) or {}

    conn = get_db()
    
    try:
        if 'createUser' in query and 'createUser' in data:
            user_data = data['createUser']
            if user_data:
                user_id = user_data['id']
                username = variables.get('username')
                number_id = variables.get('number_id')
                first_name = variables.get('first_name')
                last_name = variables.get('last_name')
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO users (id, username, number_id, first_name, last_name)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, username, number_id, first_name, last_name))
        
        elif 'createCompany' in query and 'createCompany' in data:
            comp_data = data['createCompany']
            if comp_data:
                comp_id = comp_data['id']
                inp = variables.get('input', {})
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO companies (id, name, slug, description, owner_user_id, data)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (comp_id, inp.get('name'), inp.get('slug'), inp.get('description'), inp.get('owner_user_id'), json.dumps(inp.get('data') or {})))
        
        elif 'createDomain' in query and 'createDomain' in data:
            dom_data = data['createDomain']
            if dom_data:
                dom_id = dom_data['id']
                inp = variables.get('input', {})
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO domains (id, company_id, host, canonical_url, data)
                    VALUES (?, ?, ?, ?, ?)
                """, (dom_id, inp.get('company_id'), inp.get('host'), inp.get('canonical_url'), json.dumps(inp.get('data') or {})))
        
        elif 'createPeople' in query and 'createPeople' in data:
            p_data = data['createPeople']
            if p_data:
                p_id = p_data['id']
                inp = variables.get('input', {})
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO people (id, company_id, created_by, given_name, family_name, emails, phones, notes, data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (p_id, inp.get('company_id'), inp.get('created_by'), inp.get('given_name'), inp.get('family_name'), json.dumps(inp.get('emails') or []), json.dumps(inp.get('phones') or []), inp.get('notes'), json.dumps(inp.get('data') or {})))
        
        elif 'updateHttpxResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM companies WHERE slug = ? OR lower(name) = lower(?) LIMIT 1", (domain, domain))
            comp_row = cursor.fetchone()
            company_id = comp_row[0] if comp_row else None

            for res in results:
                raw_url = res.get('url', '')
                input_host = res.get('input', '')
                if input_host:
                    host = input_host.strip().lower()
                else:
                    host = re.sub(r'^https?://', '', raw_url).split('/')[0].split(':')[0].strip().lower()
                
                if not host:
                    continue

                patch = {
                    "title": res.get("title", ""),
                    "webserver": res.get("webserver", ""),
                    "status_code": res.get("status_code", 0),
                    "headers": res.get("header", {}),
                    "tech": res.get("tech", []),
                    "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }

                cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?)", (host,))
                d_row = cursor.fetchone()
                if d_row:
                    update_domain_data(conn, host, patch)
                elif company_id:
                    dom_id = str(uuid.uuid4())
                    cursor.execute("""
                        INSERT OR REPLACE INTO domains (id, company_id, host, canonical_url, data)
                        VALUES (?, ?, ?, ?, ?)
                    """, (dom_id, company_id, host, raw_url or f"https://{host}", json.dumps(patch)))
            conn.commit()
        
        elif 'updatePortScanResults' in query:
            domain = variables.get('domain')
            ports = variables.get('ports', [])
            ips = variables.get('ips', [])
            cursor = conn.cursor()
            cursor.execute("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            row = cursor.fetchone()
            if row:
                company_id = row[0]
                cursor.execute("SELECT data FROM companies WHERE id = ?", (company_id,))
                c_row = cursor.fetchone()
                try:
                    comp_data = json.loads(c_row[0] or '{}') if c_row else {}
                except:
                    comp_data = {}
                comp_data["ports"] = ports
                comp_data["ips"] = ips
                comp_data["last_port_scan"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                comp_data["phase"] = "3"
                cursor.execute(
                    "UPDATE companies SET data = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
                    (json.dumps(comp_data), company_id)
                )
        
        elif 'updateKatanaResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            cursor = conn.cursor()
            cursor.execute("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            row = cursor.fetchone()
            if row:
                company_id = row[0]
                cursor.execute("SELECT data FROM companies WHERE id = ?", (company_id,))
                c_row = cursor.fetchone()
                try:
                    comp_data = json.loads(c_row[0] or '{}') if c_row else {}
                except:
                    comp_data = {}
                comp_data["phase"] = "4"
                cursor.execute(
                    "UPDATE companies SET data = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
                    (json.dumps(comp_data), company_id)
                )
                
                for res in results:
                    host = res.get('host', '')
                    patch = {
                        "katana": {
                            "files": res.get("files", []),
                            "urls": res.get("urls", []),
                            "params": res.get("params", []),
                            "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                        }
                    }
                    update_domain_data(conn, host, patch)
        
        elif 'updateNucleiResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', {}) or {}
            cursor = conn.cursor()
            cursor.execute("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            row = cursor.fetchone()
            if row:
                company_id = row[0]
                cursor.execute("SELECT data FROM companies WHERE id = ?", (company_id,))
                c_row = cursor.fetchone()
                try:
                    comp_data = json.loads(c_row[0] or '{}') if c_row else {}
                except:
                    comp_data = {}
                comp_data["phase"] = "5"
                cursor.execute(
                    "UPDATE companies SET data = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
                    (json.dumps(comp_data), company_id)
                )
                
                for url, vulns in results.items():
                    stripped = url.replace("https://", "").replace("http://", "").split("/")[0]
                    patch = {
                        "nuclei": vulns,
                        "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                    }
                    cursor.execute(
                        "SELECT host FROM domains WHERE lower(canonical_url) = lower(?) OR lower(host) = lower(?)",
                        (url, stripped)
                    )
                    hosts = [r[0] for r in cursor.fetchall()]
                    for h in hosts:
                        update_domain_data(conn, h, patch)

        elif 'updateJsResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            for res in results:
                host = res.get('host', domain)
                patch = {
                    "js_findings": res.get("findings", []),
                    "js_endpoints": res.get("endpoints", []),
                    "last_js_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }
                update_domain_data(conn, host, patch)

        elif 'updateExposureResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            for res in results:
                host = res.get('host', domain)
                patch = {
                    "exposures": res.get("exposures", []),
                    "last_exposure_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }
                update_domain_data(conn, host, patch)

        elif 'updateTakeoverResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            for res in results:
                host = res.get('host', domain)
                patch = {
                    "takeover": res.get("takeover", None),
                    "last_takeover_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }
                update_domain_data(conn, host, patch)

        elif 'createFindingsBatch' in query:
            domain = variables.get('domain')
            findings = variables.get('findings', []) or []
            cursor = conn.cursor()
            cursor.execute("SELECT id, company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            company_id = dom_row[1] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for f in findings:
                f_id = f.get('id') or str(uuid.uuid4())
                cursor.execute("""
                    INSERT OR REPLACE INTO findings (id, domain_id, company_id, tool, severity, vuln_type, title, url, description, evidence, poc, cve, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f_id, domain_id, company_id,
                    f.get('tool', 'unknown'),
                    f.get('severity', 'info'),
                    f.get('vuln_type', 'vuln'),
                    f.get('title', 'Untitled Finding'),
                    f.get('url', ''),
                    f.get('description', ''),
                    f.get('evidence', ''),
                    f.get('poc', ''),
                    f.get('cve', ''),
                    f.get('status', 'open'),
                    now, now
                ))

        elif 'createEndpointsBatch' in query:
            domain = variables.get('domain')
            endpoints = variables.get('endpoints', []) or []
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for ep in endpoints:
                ep_id = ep.get('id') or str(uuid.uuid4())
                params = ep.get('params', [])
                if isinstance(params, list):
                    params = json.dumps(params)
                cursor.execute("""
                    INSERT OR REPLACE INTO endpoints (id, domain_id, url, method, params, status_code, content_type, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ep_id, domain_id,
                    ep.get('url', ''),
                    ep.get('method', 'GET'),
                    params,
                    ep.get('status_code'),
                    ep.get('content_type', ''),
                    ep.get('source', 'crawler'),
                    now
                ))

        elif 'createSecretsBatch' in query:
            domain = variables.get('domain')
            secrets = variables.get('secrets', []) or []
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for s in secrets:
                s_id = s.get('id') or str(uuid.uuid4())
                cursor.execute("""
                    INSERT OR REPLACE INTO secrets (id, domain_id, rule_name, secret_type, match_snippet, file_url, severity, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    s_id, domain_id,
                    s.get('rule_name', 'Generic Secret'),
                    s.get('secret_type', 'api_key'),
                    s.get('match_snippet', ''),
                    s.get('file_url', ''),
                    s.get('severity', 'high'),
                    s.get('status', 'open'),
                    now
                ))

        elif 'createNetworkServicesBatch' in query:
            domain = variables.get('domain')
            services = variables.get('services', []) or []
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for s in services:
                s_id = s.get('id') or str(uuid.uuid4())
                cursor.execute("""
                    INSERT OR REPLACE INTO network_services (id, domain_id, ip, port, protocol, service, product, version, banner, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    s_id, domain_id,
                    s.get('ip', ''),
                    int(s.get('port', 0)),
                    s.get('protocol', 'tcp'),
                    s.get('service', ''),
                    s.get('product', ''),
                    s.get('version', ''),
                    s.get('banner', ''),
                    now
                ))

        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Error executing GraphQL mutation locally: {e}")
    finally:
        conn.close()
def query_graphql(in_file):
    try:
        with open(in_file, 'r') as f:
            payload = json.load(f)
        os.remove(in_file)
    except Exception as e:
        print(json.dumps({"errors": [{"message": f"Error loading query file: {e}"}]}))
        return

    query = payload.get('query', '')
    variables = payload.get('variables', {}) or {}

    conn = get_db()
    cursor = conn.cursor()
    response_data = {}

    try:
        if 'GetUserByNumberId' in query:
            num_id = variables.get('numId')
            cursor.execute("SELECT id FROM users WHERE number_id = ?", (num_id,))
            row = cursor.fetchone()
            response_data = {"user": {"id": row['id']} if row else None}
        
        elif 'GetUserByUsername' in query:
            username = variables.get('username')
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            response_data = {"user": {"id": row['id']} if row else None}
        
        elif 'GetCompanyBySlug' in query:
            slug = variables.get('slug')
            cursor.execute("SELECT id, name, slug, description, owner_user_id, data FROM companies WHERE slug = ?", (slug,))
            row = cursor.fetchone()
            if row:
                try:
                    c_data = json.loads(row['data'] or '{}')
                except:
                    c_data = {}
                response_data = {
                    "companyBySlug": {
                        "id": row['id'],
                        "name": row['name'],
                        "slug": row['slug'],
                        "description": row['description'],
                        "owner_user_id": row['owner_user_id'],
                        "data": c_data
                    }
                }
            else:
                response_data = {"companyBySlug": None}

        elif 'domainsToScan' in query:
            cursor.execute("SELECT slug FROM companies WHERE created_at = updated_at ORDER BY slug")
            rows = cursor.fetchall()
            response_data = {"domainsToScan": [{"slug": r['slug']} for r in rows]}

        elif 'companies' in query:
            cursor.execute("SELECT id FROM companies LIMIT 1")
            rows = cursor.fetchall()
            response_data = {"companies": [{"id": r['id']} for r in rows]}
            
        elif 'createUser' in query:
            user_id = str(uuid.uuid4())
            username = variables.get('username')
            number_id = variables.get('number_id')
            first_name = variables.get('first_name')
            last_name = variables.get('last_name')
            cursor.execute("""
                INSERT OR REPLACE INTO users (id, username, number_id, first_name, last_name)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, username, number_id, first_name, last_name))
            conn.commit()
            response_data = {"createUser": {"id": user_id, "username": username}}
            
        elif 'createCompany' in query:
            comp_id = str(uuid.uuid4())
            inp = variables.get('input', {})
            cursor.execute("""
                INSERT OR REPLACE INTO companies (id, name, slug, description, owner_user_id, data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (comp_id, inp.get('name'), inp.get('slug'), inp.get('description'), inp.get('owner_user_id'), json.dumps(inp.get('data') or {})))
            conn.commit()
            response_data = {"createCompany": {"id": comp_id, "name": inp.get('name')}}
            
        elif 'createDomain' in query:
            dom_id = str(uuid.uuid4())
            inp = variables.get('input', {})
            cursor.execute("""
                INSERT OR REPLACE INTO domains (id, company_id, host, canonical_url, data)
                VALUES (?, ?, ?, ?, ?)
            """, (dom_id, inp.get('company_id'), inp.get('host'), inp.get('canonical_url'), json.dumps(inp.get('data') or {})))
            conn.commit()
            response_data = {"createDomain": {"id": dom_id}}
            
        elif 'createPeople' in query:
            p_id = str(uuid.uuid4())
            inp = variables.get('input', {})
            cursor.execute("""
                INSERT OR REPLACE INTO people (id, company_id, created_by, given_name, family_name, emails, phones, notes, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (p_id, inp.get('company_id'), inp.get('created_by'), inp.get('given_name'), inp.get('family_name'), json.dumps(inp.get('emails') or []), json.dumps(inp.get('phones') or []), inp.get('notes'), json.dumps(inp.get('data') or {})))
            conn.commit()
            response_data = {"createPeople": {"id": p_id}}
            
        elif 'updateHttpxResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM companies WHERE slug = ? OR lower(name) = lower(?) LIMIT 1", (domain, domain))
            comp_row = cursor.fetchone()
            company_id = comp_row[0] if comp_row else None

            for res in results:
                raw_url = res.get('url', '')
                input_host = res.get('input', '')
                if input_host:
                    host = input_host.strip().lower()
                else:
                    host = re.sub(r'^https?://', '', raw_url).split('/')[0].split(':')[0].strip().lower()
                
                if not host:
                    continue

                patch = {
                    "title": res.get("title", ""),
                    "webserver": res.get("webserver", ""),
                    "status_code": res.get("status_code", 0),
                    "headers": res.get("header", {}),
                    "tech": res.get("tech", []),
                    "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }

                cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?)", (host,))
                d_row = cursor.fetchone()
                if d_row:
                    update_domain_data(conn, host, patch)
                elif company_id:
                    dom_id = str(uuid.uuid4())
                    cursor.execute("""
                        INSERT OR REPLACE INTO domains (id, company_id, host, canonical_url, data)
                        VALUES (?, ?, ?, ?, ?)
                    """, (dom_id, company_id, host, raw_url or f"https://{host}", json.dumps(patch)))
            conn.commit()
            response_data = {"updateHttpxResults": True}
            
        elif 'updatePortScanResults' in query:
            domain = variables.get('domain')
            ports = variables.get('ports', [])
            ips = variables.get('ips', [])
            cursor.execute("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            row = cursor.fetchone()
            if row:
                company_id = row[0]
                cursor.execute("SELECT data FROM companies WHERE id = ?", (company_id,))
                c_row = cursor.fetchone()
                try:
                    comp_data = json.loads(c_row[0] or '{}') if c_row else {}
                except:
                    comp_data = {}
                comp_data["ports"] = ports
                comp_data["ips"] = ips
                comp_data["last_port_scan"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                comp_data["phase"] = "3"
                cursor.execute(
                    "UPDATE companies SET data = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
                    (json.dumps(comp_data), company_id)
                )
            conn.commit()
            response_data = {"updatePortScanResults": True}
            
        elif 'updateKatanaResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            cursor.execute("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            row = cursor.fetchone()
            if row:
                company_id = row[0]
                cursor.execute("SELECT data FROM companies WHERE id = ?", (company_id,))
                c_row = cursor.fetchone()
                try:
                    comp_data = json.loads(c_row[0] or '{}') if c_row else {}
                except:
                    comp_data = {}
                comp_data["phase"] = "4"
                cursor.execute(
                    "UPDATE companies SET data = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
                    (json.dumps(comp_data), company_id)
                )
                
                for res in results:
                    host = res.get('host', '')
                    patch = {
                        "katana": {
                            "files": res.get("files", []),
                            "urls": res.get("urls", []),
                            "params": res.get("params", []),
                            "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                        }
                    }
                    update_domain_data(conn, host, patch)
            conn.commit()
            response_data = {"updateKatanaResults": True}
            
        elif 'updateNucleiResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', {}) or {}
            cursor.execute("SELECT company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            row = cursor.fetchone()
            if row:
                company_id = row[0]
                cursor.execute("SELECT data FROM companies WHERE id = ?", (company_id,))
                c_row = cursor.fetchone()
                try:
                    comp_data = json.loads(c_row[0] or '{}') if c_row else {}
                except:
                    comp_data = {}
                comp_data["phase"] = "5"
                cursor.execute(
                    "UPDATE companies SET data = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
                    (json.dumps(comp_data), company_id)
                )
                
                for url, vulns in results.items():
                    stripped = url.replace("https://", "").replace("http://", "").split("/")[0]
                    patch = {
                        "nuclei": vulns,
                        "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                    }
                    cursor.execute(
                        "SELECT host FROM domains WHERE lower(canonical_url) = lower(?) OR lower(host) = lower(?)",
                        (url, stripped)
                    )
                    hosts = [r[0] for r in cursor.fetchall()]
                    for h in hosts:
                        update_domain_data(conn, h, patch)
        elif 'updateJsResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            for res in results:
                host = res.get('host', domain)
                patch = {
                    "js_findings": res.get("findings", []),
                    "js_endpoints": res.get("endpoints", []),
                    "last_js_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }
                update_domain_data(conn, host, patch)
            conn.commit()
            response_data = {"updateJsResults": True}

        elif 'updateExposureResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
            for res in results:
                host = res.get('host', domain)
                patch = {
                    "exposures": res.get("exposures", []),
                    "last_exposure_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }
                update_domain_data(conn, host, patch)
            conn.commit()
            response_data = {"updateExposureResults": True}

        elif 'updateTakeoverResults' in query:
            domain = variables.get('domain')
            results = variables.get('results', []) or []
        elif 'createFindingsBatch' in query:
            domain = variables.get('domain')
            findings = variables.get('findings', []) or []
            cursor.execute("SELECT id, company_id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            company_id = dom_row[1] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for f in findings:
                f_id = f.get('id') or str(uuid.uuid4())
                cursor.execute("""
                    INSERT OR REPLACE INTO findings (id, domain_id, company_id, tool, severity, vuln_type, title, url, description, evidence, poc, cve, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f_id, domain_id, company_id,
                    f.get('tool', 'unknown'),
                    f.get('severity', 'info'),
                    f.get('vuln_type', 'vuln'),
                    f.get('title', 'Untitled Finding'),
                    f.get('url', ''),
                    f.get('description', ''),
                    f.get('evidence', ''),
                    f.get('poc', ''),
                    f.get('cve', ''),
                    f.get('status', 'open'),
                    now, now
                ))
            conn.commit()
            response_data = {"createFindingsBatch": True}

        elif 'createEndpointsBatch' in query:
            domain = variables.get('domain')
            endpoints = variables.get('endpoints', []) or []
            cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for ep in endpoints:
                ep_id = ep.get('id') or str(uuid.uuid4())
                params = ep.get('params', [])
                if isinstance(params, list):
                    params = json.dumps(params)
                cursor.execute("""
                    INSERT OR REPLACE INTO endpoints (id, domain_id, url, method, params, status_code, content_type, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ep_id, domain_id,
                    ep.get('url', ''),
                    ep.get('method', 'GET'),
                    params,
                    ep.get('status_code'),
                    ep.get('content_type', ''),
                    ep.get('source', 'crawler'),
                    now
                ))
            conn.commit()
            response_data = {"createEndpointsBatch": True}

        elif 'createSecretsBatch' in query:
            domain = variables.get('domain')
            secrets = variables.get('secrets', []) or []
            cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for s in secrets:
                s_id = s.get('id') or str(uuid.uuid4())
                cursor.execute("""
                    INSERT OR REPLACE INTO secrets (id, domain_id, rule_name, secret_type, match_snippet, file_url, severity, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    s_id, domain_id,
                    s.get('rule_name', 'Generic Secret'),
                    s.get('secret_type', 'api_key'),
                    s.get('match_snippet', ''),
                    s.get('file_url', ''),
                    s.get('severity', 'high'),
                    s.get('status', 'open'),
                    now
                ))
            conn.commit()
            response_data = {"createSecretsBatch": True}

        elif 'createNetworkServicesBatch' in query:
            domain = variables.get('domain')
            services = variables.get('services', []) or []
            cursor.execute("SELECT id FROM domains WHERE lower(host) = lower(?) LIMIT 1", (domain,))
            dom_row = cursor.fetchone()
            domain_id = dom_row[0] if dom_row else None
            now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
            for s in services:
                s_id = s.get('id') or str(uuid.uuid4())
                cursor.execute("""
                    INSERT OR REPLACE INTO network_services (id, domain_id, ip, port, protocol, service, product, version, banner, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    s_id, domain_id,
                    s.get('ip', ''),
                    int(s.get('port', 0)),
                    s.get('protocol', 'tcp'),
                    s.get('service', ''),
                    s.get('product', ''),
                    s.get('version', ''),
                    s.get('banner', ''),
                    now
                ))
            conn.commit()
            response_data = {"createNetworkServicesBatch": True}

        print(json.dumps({"data": response_data}))
    except Exception as e:
        conn.rollback()
        print(json.dumps({"errors": [{"message": f"SQLite execution failed: {e}"}]}))
    finally:
        conn.close()

def get_findings_for_domain(domain_or_slug, severity=None):
    conn = get_db()
    cursor = conn.cursor()
    query = """
        SELECT f.id, f.tool, f.severity, f.vuln_type, f.title, f.url, f.description, f.evidence, f.poc, f.cve, f.status, f.created_at, d.host
        FROM findings f
        JOIN domains d ON f.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?)
    """
    params = [domain_or_slug, domain_or_slug, domain_or_slug]
    if severity:
        query += " AND lower(f.severity) = lower(?)"
        params.append(severity)
    query += " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.created_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    findings = [dict(r) for r in rows]
    conn.close()
    return findings

def save_ai_review(domain_or_slug, skill, model, output):
    """Store a BYOK AI assistant review (ai_assistant.py) against whichever
    company the domain/slug resolves to. Never stores the provider API key
    or raw secret values — only the model's analyst-facing output text."""
    conn = get_db()
    company_id = _resolve_company_id(conn, domain_or_slug.lower())
    review_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO ai_reviews (id, domain_id, company_id, skill, model, output) "
        "VALUES (?, NULL, ?, ?, ?, ?)",
        (review_id, company_id, skill, model, output),
    )
    conn.commit()
    conn.close()
    return review_id


def get_ai_reviews(domain_or_slug, limit=10):
    conn = get_db()
    company_id = _resolve_company_id(conn, domain_or_slug.lower())
    cur = conn.cursor()
    cur.execute(
        "SELECT skill, model, output, created_at FROM ai_reviews "
        "WHERE company_id = ? ORDER BY created_at DESC LIMIT ?",
        (company_id, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_secrets_for_domain(domain_or_slug):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.id, s.rule_name, s.secret_type, s.match_snippet, s.file_url, s.severity, s.status, s.created_at, d.host
        FROM secrets s
        JOIN domains d ON s.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?)
        ORDER BY s.created_at DESC
    """, (domain_or_slug, domain_or_slug, domain_or_slug))
    rows = cursor.fetchall()
    secrets = [dict(r) for r in rows]
    conn.close()
    return secrets

def get_services_for_domain(domain_or_slug):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ns.id, ns.ip, ns.port, ns.protocol, ns.service, ns.product, ns.version, ns.banner, ns.created_at, d.host
        FROM network_services ns
        JOIN domains d ON ns.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?)
        ORDER BY ns.port ASC
    """, (domain_or_slug, domain_or_slug, domain_or_slug))
    rows = cursor.fetchall()
    services = [dict(r) for r in rows]
    conn.close()
    return services

def get_endpoints_for_domain(domain_or_slug, limit=200):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.id, e.url, e.method, e.params, e.status_code, e.content_type, e.source, e.created_at, d.host
        FROM endpoints e
        JOIN domains d ON e.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE lower(d.host) = lower(?) OR lower(c.slug) = lower(?) OR lower(c.name) = lower(?)
        ORDER BY e.created_at DESC LIMIT ?
    """, (domain_or_slug, domain_or_slug, domain_or_slug, limit))
    rows = cursor.fetchall()
    endpoints = [dict(r) for r in rows]
    conn.close()
    return endpoints

def generate_report(domain_or_slug):
    target = get_target_details(domain_or_slug)
    findings = get_findings_for_domain(domain_or_slug)
    secrets = get_secrets_for_domain(domain_or_slug)
    services = get_services_for_domain(domain_or_slug)
    endpoints = get_endpoints_for_domain(domain_or_slug, limit=50)

    stats = {
        "critical": len([f for f in findings if f['severity'].lower() == 'critical']),
        "high": len([f for f in findings if f['severity'].lower() == 'high']),
        "medium": len([f for f in findings if f['severity'].lower() == 'medium']),
        "low": len([f for f in findings if f['severity'].lower() == 'low']),
        "info": len([f for f in findings if f['severity'].lower() == 'info']),
        "secrets": len(secrets),
        "services": len(services),
        "endpoints": len(endpoints),
        "domains": len(target['domains']) if target else 0
    }
    return {
        "target": target,
        "stats": stats,
        "findings": findings,
        "secrets": secrets,
        "services": services,
        "endpoints": endpoints
    }

# ---------------------------------------------------------------------------
# Report exporters: SARIF 2.1.0 (CI ingestion) and STIX 2.1 (threat intel).
# ---------------------------------------------------------------------------

# Approximate CVSS v3.1 base scores + SARIF levels per severity bucket. These
# are coarse defaults used when a finding carries no explicit score.
_SEVERITY_MODEL = {
    "critical": {"cvss": 9.5, "sarif": "error", "rank": 5},
    "high":     {"cvss": 8.0, "sarif": "error", "rank": 4},
    "medium":   {"cvss": 5.5, "sarif": "warning", "rank": 3},
    "low":      {"cvss": 3.1, "sarif": "note", "rank": 2},
    "info":     {"cvss": 0.0, "sarif": "note", "rank": 1},
}


def severity_model(severity):
    """Normalize a free-form severity string to the CVSS/SARIF/rank model."""
    return _SEVERITY_MODEL.get((severity or "info").strip().lower(), _SEVERITY_MODEL["info"])


def _redact(value, keep=4):
    """Redact a secret value, keeping only a short prefix for correlation."""
    if not value:
        return ""
    s = str(value)
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "…[redacted]"


def report_sarif(report, include_secrets=False):
    """Render a report dict as a SARIF 2.1.0 log (CWE/severity aware)."""
    findings = report.get("findings") or []
    secrets = report.get("secrets") or []

    rules = {}
    results = []

    def add_result(rule_id, rule_name, level, message, uri, props):
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
            }
        loc = []
        if uri:
            loc = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": loc,
            "properties": props,
        })

    for f in findings:
        model = severity_model(f.get("severity"))
        vt = (f.get("vuln_type") or "finding").strip() or "finding"
        rule_id = f"chack/{vt}"
        props = {
            "security-severity": str(model["cvss"]),
            "severity": (f.get("severity") or "info"),
            "tool": f.get("tool") or "",
            "cve": f.get("cve") or "",
        }
        msg = f.get("title") or vt
        if f.get("description"):
            msg = f"{msg}: {f['description']}"
        add_result(rule_id, vt, model["sarif"], msg,
                   f.get("url") or f.get("host") or "", props)

    for s in secrets:
        model = severity_model(s.get("severity") or "high")
        snippet = s.get("match_snippet") or ""
        if not include_secrets:
            snippet = _redact(snippet)
        add_result("chack/secret", "leaked-secret", model["sarif"],
                   f"{s.get('rule_name') or 'secret'} ({s.get('secret_type') or 'unknown'}): {snippet}",
                   s.get("file_url") or s.get("host") or "",
                   {"security-severity": str(model["cvss"]),
                    "severity": s.get("severity") or "high",
                    "secret_type": s.get("secret_type") or ""})

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "cHack",
                "informationUri": "https://github.com/chethober/cHack",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def report_stix(report, include_secrets=False):
    """Render a report dict as a STIX 2.1 bundle (vulnerabilities + indicators)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = []

    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": now, "modified": now,
        "name": "cHack", "identity_class": "system",
    })

    def obj(d):
        d.setdefault("spec_version", "2.1")
        d.setdefault("created", now)
        d.setdefault("modified", now)
        d.setdefault("created_by_ref", identity_id)
        objects.append(d)

    for f in report.get("findings") or []:
        model = severity_model(f.get("severity"))
        name = f.get("title") or (f.get("vuln_type") or "finding")
        desc = f.get("description") or ""
        if f.get("cve"):
            obj({
                "type": "vulnerability", "id": f"vulnerability--{uuid.uuid4()}",
                "name": f.get("cve"),
                "description": f"{name}: {desc}".strip(": "),
                "external_references": [{"source_name": "cve", "external_id": f.get("cve")}],
                "labels": [f.get("severity") or "info"],
            })
        if f.get("url"):
            obj({
                "type": "observed-data", "id": f"observed-data--{uuid.uuid4()}",
                "first_observed": now, "last_observed": now, "number_observed": 1,
                "objects": {"0": {"type": "url", "value": f.get("url")}},
                "labels": [f.get("vuln_type") or "finding", f.get("severity") or "info"],
            })

    for ns in report.get("services") or []:
        ip = ns.get("ip")
        port = ns.get("port")
        if not ip:
            continue
        obj({
            "type": "observed-data", "id": f"observed-data--{uuid.uuid4()}",
            "first_observed": now, "last_observed": now, "number_observed": 1,
            "objects": {
                "0": {"type": "ipv4-addr", "value": ip},
                "1": {"type": "network-traffic", "dst_ref": "0",
                      "dst_port": port, "protocols": [ns.get("protocol") or "tcp"]},
            },
            "labels": ["network-service", ns.get("service") or "unknown"],
        })

    for s in report.get("secrets") or []:
        snippet = s.get("match_snippet") or ""
        if not include_secrets:
            snippet = _redact(snippet)
        obj({
            "type": "indicator", "id": f"indicator--{uuid.uuid4()}",
            "name": f"Leaked {s.get('secret_type') or 'secret'}: {s.get('rule_name') or ''}".strip(),
            "description": f"Snippet: {snippet}; source: {s.get('file_url') or s.get('host') or ''}",
            "indicator_types": ["compromised"],
            "pattern": f"[x-chack:secret_type = '{s.get('secret_type') or 'unknown'}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [s.get("severity") or "high"],
        })

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def get_all_targets():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.id, c.name, c.slug, c.description, c.data as company_data, c.created_at, c.updated_at,
               COUNT(d.id) as domain_count
        FROM companies c
        LEFT JOIN domains d ON d.company_id = c.id
        GROUP BY c.id
        ORDER BY c.updated_at DESC
    """)
    rows = cursor.fetchall()
    targets = []
    for r in rows:
        try:
            cdata = json.loads(r['company_data'] or '{}')
        except:
            cdata = {}
        targets.append({
            "id": r['id'],
            "name": r['name'],
            "slug": r['slug'],
            "description": r['description'],
            "data": cdata,
            "created_at": r['created_at'],
            "updated_at": r['updated_at'],
            "domain_count": r['domain_count']
        })
    conn.close()
    return targets

def get_target_details(slug_or_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, slug, description, data, created_at, updated_at FROM companies WHERE slug = ? OR id = ?", (slug_or_id, slug_or_id))
    comp = cursor.fetchone()
    if not comp:
        conn.close()
        return None
    
    try:
        cdata = json.loads(comp['data'] or '{}')
    except:
        cdata = {}
    
    cursor.execute("SELECT id, host, canonical_url, data, created_at, updated_at FROM domains WHERE company_id = ? ORDER BY host", (comp['id'],))
    dom_rows = cursor.fetchall()
    domains = []
    for d in dom_rows:
        try:
            ddata = json.loads(d['data'] or '{}')
        except:
            ddata = {}
        domains.append({
            "id": d['id'],
            "host": d['host'],
            "canonical_url": d['canonical_url'],
            "data": ddata,
            "created_at": d['created_at'],
            "updated_at": d['updated_at']
        })
    conn.close()
    return {
        "company": {
            "id": comp['id'],
            "name": comp['name'],
            "slug": comp['slug'],
            "description": comp['description'],
            "data": cdata,
            "created_at": comp['created_at'],
            "updated_at": comp['updated_at']
        },
        "domains": domains
    }

def get_all_jobs(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, command, domain, runner, status, LENGTH(COALESCE(stdout,'')) as stdout_len, created_at, updated_at FROM scan_jobs ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    jobs = [dict(r) for r in rows]
    conn.close()
    return jobs

def get_job_log(job_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT stdout FROM scan_jobs WHERE id = ?", (job_id,))
    row = cursor.fetchone()
    conn.close()
    return row['stdout'] if row else ""

def get_db_summary():
    conn = get_db()
    cursor = conn.cursor()
    summary = {
        'companies': 0,
        'domains': 0,
        'users': 0,
        'people': 0,
        'jobs': 0,
        'findings': 0,
        'secrets': 0,
        'endpoints': 0,
        'services': 0,
        'findings_by_severity': {},
        'recent_jobs': [],
        'recent_companies': []
    }
    try:
        cursor.execute("SELECT COUNT(*) FROM companies")
        summary['companies'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM domains")
        summary['domains'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM users")
        summary['users'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM people")
        summary['people'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_jobs")
        summary['jobs'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM findings")
        summary['findings'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM secrets")
        summary['secrets'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM endpoints")
        summary['endpoints'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM network_services")
        summary['services'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        summary['findings_by_severity'] = dict(cursor.fetchall())
        
        cursor.execute("SELECT id, command, domain, status, created_at FROM scan_jobs ORDER BY created_at DESC LIMIT 5")
        summary['recent_jobs'] = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT name, slug, created_at FROM companies ORDER BY created_at DESC LIMIT 5")
        summary['recent_companies'] = [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        summary['error'] = str(e)
    conn.close()
    return summary

# Risk scoring: weighted contribution of each open finding/secret by severity.
SEVERITY_WEIGHTS = {'critical': 10, 'high': 6, 'medium': 3, 'low': 1, 'info': 0}


def _redact_secret(snippet):
    """Mask the middle of a credential match so search results don't leak the
    raw value. Keeps a few leading/trailing chars for recognisability."""
    if not snippet:
        return ""
    s = str(snippet)
    if len(s) <= 12:
        return s[:2] + "***"
    return s[:4] + "***" + s[-4:]


def _risk_scores(conn, min_score=0.0):
    """Derive a per-target (company) risk score from open findings and secrets.

    No risk column is stored; the score is aggregated on demand as the weighted
    sum of open findings and secrets by severity. Returns targets ordered by
    score descending, filtered to score >= min_score.
    """
    cursor = conn.cursor()
    scores = {}  # company_id -> dict

    cursor.execute("SELECT id, name, slug FROM companies")
    for r in cursor.fetchall():
        scores[r['id']] = {
            "company_id": r['id'], "name": r['name'], "slug": r['slug'],
            "score": 0.0, "findings": 0, "secrets": 0,
            "by_severity": {k: 0 for k in SEVERITY_WEIGHTS},
        }

    cursor.execute("SELECT company_id, severity, COUNT(*) AS n FROM findings WHERE status = 'open' AND company_id IS NOT NULL GROUP BY company_id, severity")
    for r in cursor.fetchall():
        t = scores.get(r['company_id'])
        if not t:
            continue
        sev = (r['severity'] or 'info').lower()
        t['score'] += SEVERITY_WEIGHTS.get(sev, 0) * r['n']
        t['findings'] += r['n']
        if sev in t['by_severity']:
            t['by_severity'][sev] += r['n']

    # Secrets have no company_id column; join through the owning domain.
    cursor.execute("""
        SELECT d.company_id AS cid, s.severity AS severity, COUNT(*) AS n
        FROM secrets s JOIN domains d ON s.domain_id = d.id
        WHERE s.status = 'open' AND d.company_id IS NOT NULL
        GROUP BY d.company_id, s.severity
    """)
    for r in cursor.fetchall():
        t = scores.get(r['cid'])
        if not t:
            continue
        sev = (r['severity'] or 'high').lower()
        t['score'] += SEVERITY_WEIGHTS.get(sev, 0) * r['n']
        t['secrets'] += r['n']

    results = [t for t in scores.values() if t['score'] >= min_score]
    results.sort(key=lambda t: t['score'], reverse=True)
    return results


def search_results(term, kind='all', limit=100):
    """Search stored recon results across hosts, services, tech stack, exposed
    credential patterns, findings, and derived risk score.

    kind: all | domain | service | tech | secret | finding | risk | asn
      - risk: `term` is a minimum risk score (number); returns ranked targets.
      - asn: not captured by the pipeline yet; falls back to a service/host
        keyword match and flags the gap in the response.

    Credential match snippets are redacted in results. Returns a dict with a
    `results` map keyed by category plus a `counts` summary.
    """
    kind = (kind or 'all').lower()
    like = f"%{term}%"
    out = {}
    conn = get_db()
    cursor = conn.cursor()

    if kind == 'risk':
        try:
            min_score = float(term)
        except (TypeError, ValueError):
            min_score = 0.0
        out['risk'] = _risk_scores(conn, min_score)[:limit]
        conn.close()
        return {"query": term, "kind": kind, "counts": {"risk": len(out['risk'])}, "results": out}

    note = None
    if kind == 'asn':
        note = ("ASN is not captured by the recon pipeline yet; matching hosts "
                "and network services on the term instead.")
        kind = 'all'

    if kind in ('all', 'domain'):
        cursor.execute("""
            SELECT d.host, d.canonical_url, d.data, c.slug AS company
            FROM domains d LEFT JOIN companies c ON d.company_id = c.id
            WHERE lower(d.host) LIKE lower(?) OR lower(d.data) LIKE lower(?)
            ORDER BY d.host LIMIT ?
        """, (like, like, limit))
        hits = []
        for r in cursor.fetchall():
            try:
                data = json.loads(r['data'] or '{}')
            except Exception:
                data = {}
            hits.append({
                "host": r['host'], "company": r['company'],
                "webserver": data.get('webserver', ''),
                "status_code": data.get('status_code'),
                "tech": data.get('tech', []),
                "title": data.get('title', ''),
            })
        out['domains'] = hits

    if kind in ('all', 'tech'):
        # tech stack lives in domains.data.tech (JSON array)
        cursor.execute("""
            SELECT d.host, d.data, c.slug AS company
            FROM domains d LEFT JOIN companies c ON d.company_id = c.id
            WHERE lower(d.data) LIKE lower(?)
            ORDER BY d.host LIMIT ?
        """, (f'%"tech"%{term}%', limit))
        hits = []
        for r in cursor.fetchall():
            try:
                tech = json.loads(r['data'] or '{}').get('tech', [])
            except Exception:
                tech = []
            matched = [t for t in tech if term.lower() in str(t).lower()]
            if matched:
                hits.append({"host": r['host'], "company": r['company'], "tech": tech, "matched": matched})
        out['tech'] = hits

    if kind in ('all', 'service'):
        cursor.execute("""
            SELECT d.host, ns.ip, ns.port, ns.protocol, ns.service, ns.product, ns.version, ns.banner
            FROM network_services ns JOIN domains d ON ns.domain_id = d.id
            WHERE lower(ns.service) LIKE lower(?) OR lower(ns.product) LIKE lower(?)
               OR lower(ns.version) LIKE lower(?) OR lower(ns.banner) LIKE lower(?)
               OR lower(ns.ip) LIKE lower(?) OR lower(d.host) LIKE lower(?)
            ORDER BY ns.port LIMIT ?
        """, (like, like, like, like, like, like, limit))
        out['services'] = [dict(r) for r in cursor.fetchall()]

    if kind in ('all', 'secret'):
        cursor.execute("""
            SELECT s.rule_name, s.secret_type, s.match_snippet, s.file_url, s.severity, s.status, d.host
            FROM secrets s JOIN domains d ON s.domain_id = d.id
            WHERE lower(s.rule_name) LIKE lower(?) OR lower(s.secret_type) LIKE lower(?)
            ORDER BY s.created_at DESC LIMIT ?
        """, (like, like, limit))
        hits = []
        for r in cursor.fetchall():
            row = dict(r)
            row['match_snippet'] = _redact_secret(row.get('match_snippet'))
            hits.append(row)
        out['secrets'] = hits

    if kind in ('all', 'finding'):
        cursor.execute("""
            SELECT f.tool, f.severity, f.vuln_type, f.title, f.url, f.cve, f.status, d.host
            FROM findings f JOIN domains d ON f.domain_id = d.id
            WHERE lower(f.title) LIKE lower(?) OR lower(f.vuln_type) LIKE lower(?)
               OR lower(f.cve) LIKE lower(?) OR lower(f.tool) LIKE lower(?)
            ORDER BY CASE lower(f.severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, f.created_at DESC
            LIMIT ?
        """, (like, like, like, like, limit))
        out['findings'] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    resp = {
        "query": term, "kind": kind,
        "counts": {k: len(v) for k, v in out.items()},
        "results": out,
    }
    if note:
        resp['note'] = note
    return resp


# ======================================================================
# Continuous Attack-Surface Monitoring — Drift Detection
# ======================================================================
#
# After a (re)scan completes, detect_drift() compares the current attack
# surface of a target against a rolling, runner-local baseline stored in
# `surface_assets`. Newly appeared assets are recorded in `drift_events`
# and, when a Telegram chat id is supplied, pushed as an alert.
#
# Four asset kinds are tracked:
#   subdomain   — hosts synced into the local `domains` table
#   port        — ip:port pairs from `network_services`
#   tls_cert    — certificates seen in Certificate Transparency (crt.sh)
#   cloud_asset — subdomains CNAME-pointing at known cloud providers
#
# The first time a kind is seen for a target it only seeds the baseline
# (no alert); subsequent runs alert on genuinely new assets.

# Ordered (most-specific first) CNAME substring -> cloud provider map.
_CLOUD_CNAME_PROVIDERS = [
    ("blob.core.windows.net", "Azure Blob Storage"),
    ("azurewebsites.net", "Azure App Service"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("azureedge.net", "Azure CDN"),
    ("cloudapp.azure.com", "Azure"),
    ("cloudapp.net", "Azure"),
    ("s3-website", "AWS S3 Website"),
    ("s3.amazonaws.com", "AWS S3"),
    ("elb.amazonaws.com", "AWS ELB"),
    ("cloudfront.net", "AWS CloudFront"),
    ("amazonaws.com", "AWS"),
    ("storage.googleapis.com", "GCP Cloud Storage"),
    ("appspot.com", "GCP App Engine"),
    ("run.app", "GCP Cloud Run"),
    ("ghs.google", "Google"),
    ("googleusercontent.com", "Google"),
    ("herokudns.com", "Heroku"),
    ("herokuapp.com", "Heroku"),
    ("github.io", "GitHub Pages"),
    ("pages.dev", "Cloudflare Pages"),
    ("workers.dev", "Cloudflare Workers"),
    ("cloudflare.net", "Cloudflare"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("vercel.app", "Vercel"),
    ("vercel-dns.com", "Vercel"),
    ("fastly.net", "Fastly"),
    ("fastlylb.net", "Fastly"),
    ("digitaloceanspaces.com", "DigitalOcean Spaces"),
    ("ondigitalocean.app", "DigitalOcean"),
    ("readthedocs.io", "ReadTheDocs"),
]


def _now_iso():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def _normalize_target(target):
    t = (target or "").strip().lower()
    t = re.sub(r'^[a-z]+://', '', t)   # strip scheme
    t = t.rstrip('/')
    # Strip a URL path but preserve a CIDR suffix (/<digits> at end).
    t = re.sub(r'/(?!\d+$).*$', '', t)
    return t


def _looks_like_domain(target):
    return bool(re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', target or ''))


def _resolve_company_id(conn, target):
    cur = conn.cursor()
    cur.execute(
        """
        SELECT c.id FROM companies c
        LEFT JOIN domains d ON d.company_id = c.id
        WHERE lower(c.slug) = ? OR lower(c.name) = ? OR lower(d.host) = ?
        LIMIT 1
        """,
        (target, target, target),
    )
    row = cur.fetchone()
    return row['id'] if row else None


def _collect_subdomains(conn, target):
    """Return {host: meta} for every host under the target's company."""
    assets = {}
    company_id = _resolve_company_id(conn, target)
    cur = conn.cursor()
    if company_id:
        cur.execute("SELECT host, canonical_url FROM domains WHERE company_id = ?", (company_id,))
    else:
        cur.execute("SELECT host, canonical_url FROM domains WHERE lower(host) = ?", (target,))
    for r in cur.fetchall():
        host = (r['host'] or '').strip().lower()
        if host:
            assets[host] = {"canonical_url": r['canonical_url']}
    return assets


def _collect_ports(conn, target):
    """Return {'ip:port': meta} for the target (by company, host, or IP)."""
    assets = {}
    cur = conn.cursor()
    cur.execute(
        """
        SELECT ns.ip, ns.port, ns.protocol, ns.service, ns.product, ns.version
        FROM network_services ns
        JOIN domains d ON ns.domain_id = d.id
        LEFT JOIN companies c ON d.company_id = c.id
        WHERE lower(d.host) = ? OR lower(c.slug) = ? OR lower(c.name) = ? OR ns.ip = ?
        """,
        (target, target, target, target),
    )
    for r in cur.fetchall():
        ip = (r['ip'] or '').strip()
        port = r['port']
        if not ip or port is None:
            continue
        key = f"{ip}:{port}"
        assets[key] = {
            "ip": ip,
            "port": port,
            "protocol": r['protocol'],
            "service": r['service'],
            "product": r['product'],
            "version": r['version'],
        }
    return assets


def _collect_tls_certs(target):
    """Best-effort Certificate Transparency lookup via crt.sh. {serial: meta}."""
    if not _looks_like_domain(target):
        return {}
    import urllib.request
    import urllib.parse

    assets = {}
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + target) + "&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cHack-monitor"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", "replace")
        entries = json.loads(raw)
    except Exception:
        return {}

    for e in entries[:800]:
        try:
            serial = (e.get("serial_number") or "").strip()
            key = serial or f"crtsh-{e.get('id')}"
            if not key or key in assets:
                continue
            names = (e.get("name_value") or "").replace("\n", ",")
            assets[key] = {
                "cn": e.get("common_name") or "",
                "sans": names[:300],
                "not_after": e.get("not_after") or "",
                "issuer": (e.get("issuer_name") or "")[:120],
            }
        except Exception:
            continue
    return assets


def _doh_cname(host):
    """Resolve the CNAME target for host via DNS-over-HTTPS. Returns str or ''."""
    import urllib.request
    import urllib.parse

    url = "https://dns.google/resolve?name=" + urllib.parse.quote(host) + "&type=CNAME"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cHack-monitor"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return ""
    for ans in (data.get("Answer") or []):
        if ans.get("type") == 5:  # CNAME
            return (ans.get("data") or "").rstrip(".").lower()
    return ""


def _classify_cloud(cname):
    if not cname:
        return None
    for needle, provider in _CLOUD_CNAME_PROVIDERS:
        if needle in cname:
            return provider
    return None


def _collect_cloud_assets(hosts):
    """Classify hosts whose CNAME points at a known cloud provider.

    Returns {'host -> provider': meta}. Best-effort; disabled when
    CHACK_DRIFT_CLOUD=0. Capped to keep DoH volume bounded.
    """
    if os.environ.get("CHACK_DRIFT_CLOUD", "1") == "0":
        return {}
    hosts = sorted(hosts)[:200]
    if not hosts:
        return {}

    assets = {}
    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as pool:
            cnames = list(pool.map(_doh_cname, hosts))
    except Exception:
        cnames = [_doh_cname(h) for h in hosts]

    for host, cname in zip(hosts, cnames):
        provider = _classify_cloud(cname)
        if provider:
            assets[f"{host} -> {provider}"] = {"host": host, "cname": cname, "provider": provider}
    return assets


def _send_telegram(chat_id, html):
    """Best-effort Telegram push. Token read from TELEGRAM_BOT_TOKEN env."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token or not chat_id:
        return False
    import urllib.request
    import urllib.parse

    payload = urllib.parse.urlencode({
        "chat_id": str(chat_id),
        "text": html,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode()
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=payload)
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        return True
    except Exception:
        return False


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _diff_kind(conn, target, scan_type, kind, current):
    """Diff `current` {key: meta} against the baseline for (target, kind).

    Returns (new_items, is_baseline). Updates surface_assets and
    drift_events. On a baseline (first time this kind is seen for the
    target) nothing is reported as new.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) AS n FROM surface_assets WHERE target = ? AND asset_kind = ?",
        (target, kind),
    )
    had_baseline = cur.fetchone()['n'] > 0

    # Existing keys for this (target, kind)
    cur.execute(
        "SELECT asset_key FROM surface_assets WHERE target = ? AND asset_kind = ?",
        (target, kind),
    )
    known = {r['asset_key'] for r in cur.fetchall()}

    now = _now_iso()
    new_items = []
    for key, meta in current.items():
        meta_json = json.dumps(meta, default=str)
        if key in known:
            cur.execute(
                "UPDATE surface_assets SET last_seen = ?, asset_meta = ? "
                "WHERE target = ? AND asset_kind = ? AND asset_key = ?",
                (now, meta_json, target, kind, key),
            )
            continue
        # Insert into inventory
        cur.execute(
            "INSERT OR IGNORE INTO surface_assets "
            "(id, target, asset_kind, asset_key, asset_meta, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), target, kind, key, meta_json, now, now),
        )
        if had_baseline:
            new_items.append((key, meta))
            cur.execute(
                "INSERT INTO drift_events "
                "(id, target, scan_type, asset_kind, change_type, asset_key, asset_meta, alerted, detected_at) "
                "VALUES (?, ?, ?, ?, 'new', ?, ?, 0, ?)",
                (str(uuid.uuid4()), target, scan_type, kind, key, meta_json, now),
            )
    return new_items, (not had_baseline)


def _format_drift_alert(target, scan_type, buckets):
    labels = {
        "subdomain": ("🌐", "New subdomains"),
        "port": ("🔌", "Newly exposed ports"),
        "tls_cert": ("📜", "New TLS certificates"),
        "cloud_asset": ("☁️", "New cloud assets"),
    }
    lines = [
        "🛰️ <b>Attack Surface Drift Detected</b>",
        f"Target: <code>{_esc(target)}</code> · scan: <code>{_esc(scan_type)}</code>",
    ]
    for kind in ("subdomain", "port", "tls_cert", "cloud_asset"):
        items = buckets.get(kind) or []
        if not items:
            continue
        icon, label = labels[kind]
        lines.append(f"\n{icon} <b>{label} ({len(items)})</b>")
        for key, meta in items[:15]:
            if kind == "port":
                svc = meta.get("service") or ""
                lines.append(f"• <code>{_esc(key)}</code>" + (f" ({_esc(svc)})" if svc else ""))
            elif kind == "tls_cert":
                cn = meta.get("cn") or (meta.get("sans") or "").split(",")[0]
                exp = meta.get("not_after") or ""
                extra = f" (exp {_esc(exp[:10])})" if exp else ""
                lines.append(f"• {_esc(cn) or _esc(key)}{extra}")
            else:
                lines.append(f"• <code>{_esc(key)}</code>")
        if len(items) > 15:
            lines.append(f"  …and {len(items) - 15} more")
    return "\n".join(lines)


def detect_drift(target, scan_type="scan", sender_id=None):
    """Compare current attack surface to the baseline and alert on drift.

    Returns a summary dict. Alerts via Telegram when sender_id is set and
    genuine (non-baseline) drift is found.
    """
    norm = _normalize_target(target)
    conn = get_db()
    # Ensure monitoring tables exist even on older databases.
    try:
        init_tables = conn.cursor()
        init_tables.executescript(
            "CREATE TABLE IF NOT EXISTS surface_assets (id TEXT PRIMARY KEY, target TEXT NOT NULL, "
            "asset_kind TEXT NOT NULL, asset_key TEXT NOT NULL, asset_meta TEXT DEFAULT '{}', "
            "first_seen TEXT, last_seen TEXT);"
            "CREATE UNIQUE INDEX IF NOT EXISTS surface_assets_uq ON surface_assets(target, asset_kind, asset_key);"
            "CREATE TABLE IF NOT EXISTS drift_events (id TEXT PRIMARY KEY, target TEXT NOT NULL, "
            "scan_type TEXT, asset_kind TEXT NOT NULL, change_type TEXT NOT NULL DEFAULT 'new', "
            "asset_key TEXT NOT NULL, asset_meta TEXT DEFAULT '{}', alerted INTEGER NOT NULL DEFAULT 0, "
            "detected_at TEXT);"
        )
        conn.commit()
    except Exception:
        pass

    subdomains = _collect_subdomains(conn, norm)
    ports = _collect_ports(conn, norm)
    certs = _collect_tls_certs(norm)
    cloud = _collect_cloud_assets(set(subdomains.keys()))

    buckets = {}
    baseline_kinds = []
    for kind, current in (
        ("subdomain", subdomains),
        ("port", ports),
        ("tls_cert", certs),
        ("cloud_asset", cloud),
    ):
        if not current:
            continue  # nothing collected this run → never a removal, skip
        new_items, is_baseline = _diff_kind(conn, norm, scan_type, kind, current)
        if is_baseline:
            baseline_kinds.append(kind)
        if new_items:
            buckets[kind] = new_items

    conn.commit()

    total_new = sum(len(v) for v in buckets.values())
    alerted = False
    if sender_id and total_new > 0:
        msg = _format_drift_alert(norm, scan_type, buckets)
        if _send_telegram(sender_id, msg):
            alerted = True
            cur = conn.cursor()
            cur.execute(
                "UPDATE drift_events SET alerted = 1 WHERE target = ? AND alerted = 0",
                (norm,),
            )
            conn.commit()
    conn.close()

    summary = {
        "target": norm,
        "scan_type": scan_type,
        "baseline_seeded": baseline_kinds,
        "new": {k: len(v) for k, v in buckets.items()},
        "total_new": total_new,
        "alerted": alerted,
    }
    return summary


# ===========================================================================
# Autonomous program onboarding (Phase 1) — store candidates, gate, apply.
# The scope allowlist (scope.txt) is the authorization boundary: apply_program
# is the ONLY path here that writes it, it only runs on an approved program, and
# it never emits a wildcard or an out-of-scope asset (scope_parser enforces that).
# ===========================================================================

SCOPE_FILE = os.environ.get(
    "SCOPE_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "scope.txt")
)


def _scope_hash(text):
    import hashlib
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _parse_scope_text(scope_raw, roe_raw=""):
    """Call scope_parser.parse_scope; import lazily so the module stays optional."""
    import scope_parser
    return scope_parser.parse_scope(scope_raw, roe_raw)


def onboard_program(platform, handle, name, url, scope_raw, roe_raw="", created_by=None):
    """Create/refresh a candidate program row from raw scope text.

    Runs the scope parser, stores the verbatim text + parsed proposal, and sets
    status to 'pending_approval' (awaiting the Telegram gate). Returns the stored
    program dict including the parsed proposal. Does NOT touch scope.txt.
    """
    parsed = _parse_scope_text(scope_raw, roe_raw)
    conn = get_db()
    cur = conn.cursor()
    pid = str(uuid.uuid4())
    h = _scope_hash(scope_raw)
    platform = (platform or "manual").lower()
    # Upsert on (platform, lower(handle)) when a handle is known.
    existing = None
    if handle:
        cur.execute(
            "SELECT id, status FROM bb_programs WHERE platform = ? AND lower(handle) = lower(?)",
            (platform, handle),
        )
        existing = cur.fetchone()
    if existing:
        pid = existing["id"]
        cur.execute(
            """UPDATE bb_programs SET name=?, url=?, scope_raw=?, roe_raw=?,
                 scope_parsed=?, roe_flags=?, status='pending_approval',
                 last_seen_hash=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
               WHERE id=?""",
            (name, url, scope_raw, roe_raw, json.dumps(parsed),
             json.dumps(parsed.get("roe_flags", [])), h, pid),
        )
    else:
        cur.execute(
            """INSERT INTO bb_programs
                 (id, platform, handle, name, url, scope_raw, roe_raw, scope_parsed,
                  roe_flags, status, last_seen_hash, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?)""",
            (pid, platform, handle, name, url, scope_raw, roe_raw, json.dumps(parsed),
             json.dumps(parsed.get("roe_flags", [])), h, created_by),
        )
    conn.commit()
    conn.close()
    write_audit("program.onboard", actor_number_id=created_by or 0, source="cli",
                target_type="program", target=(handle or name or url),
                detail={"platform": platform, "emit": parsed["stats"]["emit_count"],
                        "wildcards": parsed["stats"]["wildcard_count"],
                        "roe_flags": parsed["roe_flags"]})
    return get_program(pid)


def get_program(program_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM bb_programs WHERE id = ?", (program_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    for k in ("scope_parsed", "roe_flags"):
        try:
            d[k] = json.loads(d.get(k) or ("[]" if k == "roe_flags" else "{}"))
        except Exception:
            pass
    return d


def list_programs(status=None):
    conn = get_db()
    cur = conn.cursor()
    if status:
        cur.execute("SELECT id, platform, handle, name, status, created_at FROM bb_programs WHERE status = ? ORDER BY created_at DESC", (status,))
    else:
        cur.execute("SELECT id, platform, handle, name, status, created_at FROM bb_programs ORDER BY created_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def _existing_scope_entries():
    """Lowercased set of non-comment entries already in scope.txt."""
    entries = set()
    if not os.path.exists(SCOPE_FILE):
        return entries
    with open(SCOPE_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            e = line.split("#", 1)[0].strip().lower()
            if e:
                entries.add(e)
    return entries


def apply_program(program_id, decided_by=None, edited_hosts=None):
    """Append an APPROVED program's emittable hosts to scope.txt and activate it.

    edited_hosts (optional list) overrides the parser's proposal with an
    operator-edited list — but each entry is re-validated through the parser so a
    typo or a wildcard can never slip into the allowlist via the edit path.
    Returns a summary dict. This is the authorization-boundary write.
    """
    prog = get_program(program_id)
    if not prog:
        return {"error": "program not found"}
    parsed = prog.get("scope_parsed") or {}

    if edited_hosts:
        # Re-validate operator edits: feed them back through the parser.
        reparsed = _parse_scope_text("\n".join(edited_hosts))
        emit = reparsed.get("scope_txt_lines", [])
        rejected = sorted({h for h in edited_hosts} - set(emit))
    else:
        emit = parsed.get("scope_txt_lines", [])
        rejected = []

    existing = _existing_scope_entries()
    to_add = [h for h in emit if h.lower() not in existing]

    if to_add:
        label = prog.get("name") or prog.get("handle") or program_id
        platform = prog.get("platform") or "manual"
        handle = prog.get("handle") or ""
        header = f"\n# --- onboarded: {label} ({platform}/{handle}) {datetime.now(timezone.utc).strftime('%Y-%m-%d')} via cHack --onboard ---\n"
        with open(SCOPE_FILE, "a", encoding="utf-8") as f:
            f.write(header)
            for h in to_add:
                f.write(h + "\n")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE bb_programs SET status='active', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
        (program_id,),
    )
    cur.execute(
        "UPDATE pending_approvals SET status='approved', decision=?, decided_by=?, decided_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE program_id=? AND status='pending'",
        (json.dumps(to_add), decided_by, program_id),
    )
    conn.commit()
    conn.close()
    write_audit("program.apply", actor_number_id=decided_by or 0, source="cli",
                target_type="program", target=(prog.get("handle") or prog.get("name")),
                detail={"added": to_add, "rejected": rejected, "scope_file": SCOPE_FILE})
    return {"program_id": program_id, "added": to_add, "already_present": [h for h in emit if h.lower() in existing],
            "rejected": rejected, "scope_file": SCOPE_FILE, "status": "active"}


def onboard_scope_append(label, hosts):
    """Append a backend-approved host list to scope.txt (remote-apply path).

    Every host is re-validated through scope_parser before it is written, so the
    allowlist can only ever gain exact hosts/IPs/CIDRs — never a wildcard or a
    malformed entry — regardless of what the backend sent. Deduped against the
    existing file. Returns {"added": [...]}.
    """
    reparsed = _parse_scope_text("\n".join(hosts or []))
    emit = reparsed.get("scope_txt_lines", [])
    existing = _existing_scope_entries()
    to_add = [h for h in emit if h.lower() not in existing]
    if to_add:
        header = f"\n# --- onboarded: {label} {datetime.now(timezone.utc).strftime('%Y-%m-%d')} via cHack (remote apply) ---\n"
        with open(SCOPE_FILE, "a", encoding="utf-8") as f:
            f.write(header)
            for h in to_add:
                f.write(h + "\n")
    write_audit("program.apply_remote", source="daemon", target_type="program",
                target=label, detail={"added": to_add, "scope_file": SCOPE_FILE})
    return {"added": to_add, "scope_file": SCOPE_FILE}


def skip_program(program_id, decided_by=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE bb_programs SET status='skipped', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?", (program_id,))
    cur.execute("UPDATE pending_approvals SET status='skipped', decided_by=?, decided_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE program_id=? AND status='pending'", (decided_by, program_id))
    conn.commit()
    conn.close()
    write_audit("program.skip", actor_number_id=decided_by or 0, source="cli",
                target_type="program", target=program_id)
    return {"program_id": program_id, "status": "skipped"}


def main():
    if len(sys.argv) < 2:
        print("Usage: db_sqlite.py <command> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'init':
        init_db()
    elif cmd == 'audit':
        # Usage: db_sqlite.py audit <action> <source> <actor_label> <actor_number_id> \
        #                          [target_type] [target] [decision]
        if len(sys.argv) < 6:
            print("Usage: db_sqlite.py audit <action> <source> <actor_label> <actor_number_id> "
                  "[target_type] [target] [decision]")
            sys.exit(1)
        write_audit(
            action=sys.argv[2],
            source=sys.argv[3],
            actor_label=sys.argv[4],
            actor_number_id=sys.argv[5],
            target_type=(sys.argv[6] if len(sys.argv) > 6 else None),
            target=(sys.argv[7] if len(sys.argv) > 7 else None),
            decision=(sys.argv[8] if len(sys.argv) > 8 else 'allow'),
        )
    elif cmd == 'save_job':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py save_job <job_file>")
            sys.exit(1)
        save_job(sys.argv[2])
    elif cmd == 'append_log':
        if len(sys.argv) < 4:
            print("Usage: db_sqlite.py append_log <job_id> <log_base64>")
            sys.exit(1)
        append_log(sys.argv[2], sys.argv[3])
    elif cmd == 'update_status':
        if len(sys.argv) < 4:
            print("Usage: db_sqlite.py update_status <job_id> <status> [result_json]")
            sys.exit(1)
        result_arg = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
        update_status(sys.argv[2], sys.argv[3], result_arg)
    elif cmd == 'graphql':
        if len(sys.argv) < 4:
            print("Usage: db_sqlite.py graphql <in_file> <res_file>")
            sys.exit(1)
        execute_graphql(sys.argv[2], sys.argv[3])
    elif cmd == 'query':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py query <in_file>")
            sys.exit(1)
        query_graphql(sys.argv[2])
    elif cmd == 'summary' or cmd == 'stats':
        print(json.dumps(get_db_summary(), indent=2))
    elif cmd == 'targets':
        print(json.dumps(get_all_targets(), indent=2))
    elif cmd == 'target':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py target <slug_or_id>")
            sys.exit(1)
        print(json.dumps(get_target_details(sys.argv[2]), indent=2))
    elif cmd == 'jobs':
        print(json.dumps(get_all_jobs(), indent=2))
    elif cmd == 'job_log':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py job_log <job_id>")
            sys.exit(1)
        print(get_job_log(sys.argv[2]))
    elif cmd == 'findings':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py findings <domain_or_slug> [severity]")
            sys.exit(1)
        sev = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(get_findings_for_domain(sys.argv[2], sev), indent=2))
    elif cmd == 'secrets':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py secrets <domain_or_slug>")
            sys.exit(1)
        print(json.dumps(get_secrets_for_domain(sys.argv[2]), indent=2))
    elif cmd == 'services':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py services <domain_or_slug>")
            sys.exit(1)
        print(json.dumps(get_services_for_domain(sys.argv[2]), indent=2))
    elif cmd == 'endpoints':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py endpoints <domain_or_slug>")
            sys.exit(1)
        print(json.dumps(get_endpoints_for_domain(sys.argv[2]), indent=2))
    elif cmd == 'report':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py report <domain_or_slug>")
            sys.exit(1)
        print(json.dumps(generate_report(sys.argv[2]), indent=2))
    elif cmd in ('report_sarif', 'report_stix'):
        if len(sys.argv) < 3:
            print(f"Usage: db_sqlite.py {cmd} <domain_or_slug> [--include-secrets]")
            sys.exit(1)
        include_secrets = '--include-secrets' in sys.argv[3:]
        rep = generate_report(sys.argv[2])
        if cmd == 'report_sarif':
            print(json.dumps(report_sarif(rep, include_secrets), indent=2))
        else:
            print(json.dumps(report_stix(rep, include_secrets), indent=2))
    elif cmd == 'search':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py search <term> [kind]")
            print("  kind: all (default) | domain | service | tech | secret | finding | risk | asn")
            print("  risk: <term> is a minimum risk score, e.g. 'search 10 risk'")
            sys.exit(1)
        kind = sys.argv[3] if len(sys.argv) > 3 else 'all'
        print(json.dumps(search_results(sys.argv[2], kind), indent=2))
    elif cmd == 'drift':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py drift <target> [scan_type] [sender_id]")
            sys.exit(1)
        scan_type = sys.argv[3] if len(sys.argv) > 3 else 'scan'
        sender_id = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
        print(json.dumps(detect_drift(sys.argv[2], scan_type, sender_id), indent=2))
    elif cmd == 'onboard':
        # onboard <scope_file> [roe_file] --platform P --handle H --name N --url U --by ID
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py onboard <scope_file|-> [roe_file] [--platform P] [--handle H] [--name N] [--url U] [--by ID]")
            sys.exit(1)
        args = sys.argv[2:]
        opts = {}
        pos = []
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith('--'):
                opts[a[2:]] = args[i + 1] if i + 1 < len(args) else ''
                i += 2
            else:
                pos.append(a)
                i += 1
        scope_src = pos[0]
        scope_raw = sys.stdin.read() if scope_src == '-' else open(scope_src, encoding='utf-8', errors='replace').read()
        roe_raw = ''
        if len(pos) > 1 and pos[1] not in ('', '-'):
            roe_raw = open(pos[1], encoding='utf-8', errors='replace').read()
        prog = onboard_program(opts.get('platform', 'manual'), opts.get('handle'),
                               opts.get('name'), opts.get('url'), scope_raw, roe_raw,
                               int(opts['by']) if opts.get('by', '').isdigit() else None)
        print(json.dumps(prog, indent=2))
    elif cmd == 'programs':
        print(json.dumps(list_programs(sys.argv[2] if len(sys.argv) > 2 else None), indent=2))
    elif cmd == 'program':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py program <program_id>")
            sys.exit(1)
        print(json.dumps(get_program(sys.argv[2]), indent=2))
    elif cmd == 'onboard_apply':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py onboard_apply <program_id> [--by ID] [--hosts h1,h2,...]")
            sys.exit(1)
        by = None
        hosts = None
        rest = sys.argv[3:]
        for j, a in enumerate(rest):
            if a == '--by' and j + 1 < len(rest):
                by = int(rest[j + 1]) if rest[j + 1].isdigit() else None
            if a == '--hosts' and j + 1 < len(rest):
                hosts = [h.strip() for h in rest[j + 1].split(',') if h.strip()]
        print(json.dumps(apply_program(sys.argv[2], by, hosts), indent=2))
    elif cmd == 'onboard_skip':
        if len(sys.argv) < 3:
            print("Usage: db_sqlite.py onboard_skip <program_id> [by_id]")
            sys.exit(1)
        by = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else None
        print(json.dumps(skip_program(sys.argv[2], by), indent=2))
    elif cmd == 'onboard_scope_append':
        # onboard_scope_append <label> <json_array_of_hosts>
        if len(sys.argv) < 4:
            print("Usage: db_sqlite.py onboard_scope_append <label> <json_hosts>")
            sys.exit(1)
        try:
            hosts = json.loads(sys.argv[3])
        except Exception:
            hosts = [h.strip() for h in sys.argv[3].split(',') if h.strip()]
        print(json.dumps(onboard_scope_append(sys.argv[2], hosts), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == '__main__':
    main()



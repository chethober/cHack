import sys
import os
import json
import sqlite3
import base64
import uuid
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local.db")

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
    
    cursor.executescript(schema_sql)
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

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
            SET command = ?, domain = ?, runner = ?, status = ?, updated_at = ?
            WHERE id = ?
        """, (job['command'], job['domain'], job.get('runner', 'default'), job['status'], now, job['id']))
    else:
        cursor.execute("""
            INSERT INTO scan_jobs (id, command, domain, runner, status, stdout, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (job['id'], job['command'], job['domain'], job.get('runner', 'default'), job['status'], job.get('stdout', ''), now, now))
    
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

def update_status(job_id, status):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
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
            for res in results:
                raw_url = res.get('url', '')
                host = raw_url.replace("https://", "").replace("http://", "")
                patch = {
                    "title": res.get("title", ""),
                    "webserver": res.get("webserver", ""),
                    "status_code": res.get("status_code", 0),
                    "headers": res.get("header", {}),
                    "tech": res.get("tech", []),
                    "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }
                update_domain_data(conn, host, patch)
        
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
            for res in results:
                raw_url = res.get('url', '')
                host = raw_url.replace("https://", "").replace("http://", "")
                patch = {
                    "title": res.get("title", ""),
                    "webserver": res.get("webserver", ""),
                    "status_code": res.get("status_code", 0),
                    "headers": res.get("header", {}),
                    "tech": res.get("tech", []),
                    "last_scan": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
                }
                update_domain_data(conn, host, patch)
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

def main():
    if len(sys.argv) < 2:
        print("Usage: db_sqlite.py <command> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'init':
        init_db()
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
            print("Usage: db_sqlite.py update_status <job_id> <status>")
            sys.exit(1)
        update_status(sys.argv[2], sys.argv[3])
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
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == '__main__':
    main()



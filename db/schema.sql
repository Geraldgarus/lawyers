-- db/schema.sql — Tanscar Attorneys (Lawyer Case Management System)
-- Idempotent: safe to run on every server boot.

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  id              SERIAL PRIMARY KEY,
  username        VARCHAR(100) NOT NULL UNIQUE,
  email           VARCHAR(200) NOT NULL UNIQUE,
  password_hash   VARCHAR(255) NOT NULL,
  role            VARCHAR(20)  NOT NULL DEFAULT 'assistant'
                  CHECK (role IN ('lawyer','secretary','assistant')),
  full_name       VARCHAR(200) NOT NULL,
  phone           VARCHAR(50),
  is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
  failed_attempts INTEGER      NOT NULL DEFAULT 0,
  locked_until    TIMESTAMP,
  created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
-- Role is now an editable lookup (see user_roles below), not a fixed
-- three-value enum — custom roles can be assigned once created there.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;

-- ============================================================
-- USER ROLES (editable lookup). 'admin' is the one hardcoded
-- superuser role — it always has full access and is never
-- deactivatable. Every other role (including the built-in
-- Lawyer/Secretary/Assistant labels) gets its capabilities assigned
-- manually via role_capabilities below, and can be deactivated.
-- ============================================================
CREATE TABLE IF NOT EXISTS user_roles (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(50)  NOT NULL UNIQUE,   -- slug used as the stored value on users.role
  label      VARCHAR(100) NOT NULL,
  is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO user_roles (name, label) VALUES
  ('admin', 'Admin'), ('lawyer', 'Lawyer'), ('secretary', 'Secretary'), ('assistant', 'Assistant')
ON CONFLICT (name) DO NOTHING;

-- The one existing seeded admin account moves from 'lawyer' to the new
-- 'admin' role so there's always at least one account with full access;
-- a no-op after the first boot since it only ever matches that account.
UPDATE users SET role = 'admin' WHERE username = 'admin' AND email = 'admin@advocatesuite.local';

-- ============================================================
-- ROLE CAPABILITIES (which actions each role may perform — the real
-- enforcement, checked server-side on every write route via
-- requireCapability()). 'admin' bypasses this table entirely (always
-- full access) and is never stored here. The capability_key values are
-- fixed in code (server.js CAPABILITIES), not user-editable — only
-- which roles have which of them is.
-- ============================================================
CREATE TABLE IF NOT EXISTS role_capabilities (
  role_name      VARCHAR(50) NOT NULL REFERENCES user_roles(name) ON DELETE CASCADE,
  capability_key VARCHAR(50) NOT NULL,
  PRIMARY KEY (role_name, capability_key)
);

-- Seeds Lawyer/Secretary/Assistant with exactly what they could already
-- do via the old hardcoded requireRole() checks, so converting to a
-- manually-assigned matrix doesn't change anyone's access on its own —
-- ON CONFLICT DO NOTHING makes this a one-time seed, safe to leave in
-- place on every boot even after an admin has since edited the matrix.
INSERT INTO role_capabilities (role_name, capability_key) VALUES
  ('lawyer', 'create_edit_case'), ('lawyer', 'delete_case'),
  ('lawyer', 'add_edit_clients'), ('lawyer', 'delete_client'),
  ('lawyer', 'log_hearing_appointment'), ('lawyer', 'delete_hearing_appointment'),
  ('lawyer', 'upload_document'), ('lawyer', 'delete_document'),
  ('lawyer', 'create_update_task'), ('lawyer', 'delete_task'),
  ('lawyer', 'view_record_expenses'), ('lawyer', 'delete_expense'),
  ('lawyer', 'view_billing'), ('lawyer', 'manage_invoices_payments'),
  ('lawyer', 'add_case_note'), ('lawyer', 'view_reports'),
  ('lawyer', 'manage_users'), ('lawyer', 'manage_settings'),
  ('secretary', 'create_edit_case'), ('secretary', 'add_edit_clients'),
  ('secretary', 'log_hearing_appointment'), ('secretary', 'delete_hearing_appointment'),
  ('secretary', 'upload_document'), ('secretary', 'delete_document'),
  ('secretary', 'create_update_task'), ('secretary', 'delete_task'),
  ('secretary', 'view_record_expenses'), ('secretary', 'add_case_note'),
  ('assistant', 'add_edit_clients'), ('assistant', 'log_hearing_appointment'),
  ('assistant', 'upload_document'), ('assistant', 'create_update_task'),
  ('assistant', 'add_case_note')
ON CONFLICT DO NOTHING;

-- ============================================================
-- USER PAGE ACCESS (per-user page grants)
-- A user with zero rows here is "unrestricted" — sees the normal
-- role-based default page set. The moment any row is saved for a
-- user, they become "customized" and can only reach exactly the
-- pages listed here, checked both for sidebar visibility and for
-- actually loading the page.
-- ============================================================
CREATE TABLE IF NOT EXISTS user_page_access (
  user_id  INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  page_key VARCHAR(50) NOT NULL,
  PRIMARY KEY (user_id, page_key)
);
CREATE INDEX IF NOT EXISTS idx_user_page_access_user ON user_page_access(user_id);

-- ============================================================
-- ACTIVITY LOGS (audit trail)
-- ============================================================
CREATE TABLE IF NOT EXISTS activity_logs (
  id          SERIAL PRIMARY KEY,
  user_id     INT REFERENCES users(id) ON DELETE SET NULL,
  username    VARCHAR(100) NOT NULL,
  action      VARCHAR(50)  NOT NULL,   -- CREATE, UPDATE, DELETE, LOGIN, LOGOUT
  entity_type VARCHAR(50)  NOT NULL,   -- case, client, hearing, payment, user...
  entity_id   INT,
  old_data    JSONB,
  new_data    JSONB,
  ip_address  INET,
  user_agent  TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_activity_logs_user   ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_entity ON activity_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_date   ON activity_logs(created_at);

-- ============================================================
-- CLIENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS clients (
  id           SERIAL PRIMARY KEY,
  full_name    VARCHAR(200) NOT NULL,
  phone        VARCHAR(50),
  email        VARCHAR(200),
  address      TEXT,
  national_id  VARCHAR(100),
  notes        TEXT,
  created_by   INT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_clients_full_name ON clients(full_name);
CREATE INDEX IF NOT EXISTS idx_clients_phone ON clients(phone);
DROP TRIGGER IF EXISTS trg_clients_updated_at ON clients;
CREATE TRIGGER trg_clients_updated_at BEFORE UPDATE ON clients
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- CASE CATEGORIES (editable lookup — not a hardcoded enum)
-- ============================================================
CREATE TABLE IF NOT EXISTS case_categories (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(100) NOT NULL UNIQUE,   -- "Civil"
  code       VARCHAR(5)   NOT NULL UNIQUE,   -- "CV" -> case-number prefix
  is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO case_categories (name, code) VALUES
  ('Civil','CV'), ('Criminal','CR'), ('Family','FAM'), ('Land','LND'),
  ('Labour','LAB'), ('Commercial','COM'), ('Probate','PRO')
ON CONFLICT (name) DO NOTHING;

-- ============================================================
-- CASE STATUSES (editable lookup — not a hardcoded enum)
-- ============================================================
CREATE TABLE IF NOT EXISTS case_statuses (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(50)  NOT NULL UNIQUE,   -- slug used as the stored value, e.g. "intake"
  label      VARCHAR(100) NOT NULL,          -- display text, e.g. "Intake"
  is_closed  BOOLEAN      NOT NULL DEFAULT FALSE,
  sort_order INT          NOT NULL DEFAULT 0,
  is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO case_statuses (name, label, is_closed, sort_order) VALUES
  ('intake', 'Intake', FALSE, 1),
  ('active', 'Active', FALSE, 2),
  ('filed', 'Filed', FALSE, 3),
  ('in_hearing', 'In Hearing', FALSE, 4),
  ('judgment', 'Judgment', FALSE, 5),
  ('closed_won', 'Closed — Won', TRUE, 6),
  ('closed_lost', 'Closed — Lost', TRUE, 7),
  ('closed_settled', 'Closed — Settled', TRUE, 8)
ON CONFLICT (name) DO NOTHING;

-- Case status now tracks the Time Chart's court-proceeding stage (the same
-- Mention/1st PTC/Mediation/Hearing/Final PTC/Judgment/Ruling sequence used
-- by the "Court Proceeding Type" field) instead of a generic case-lifecycle
-- status. Old lifecycle statuses are deactivated, not deleted, so existing
-- cases still referencing them via the status FK keep resolving.
UPDATE case_statuses SET is_active = FALSE
  WHERE name IN ('intake','active','filed','in_hearing','closed_won','closed_lost','closed_settled');
INSERT INTO case_statuses (name, label, is_closed, sort_order, is_active) VALUES
  ('mention', 'Mention', FALSE, 1, TRUE),
  ('first_ptc', '1st PTC', FALSE, 2, TRUE),
  ('mediation', 'Mediation', FALSE, 3, TRUE),
  ('hearing', 'Hearing', FALSE, 4, TRUE),
  ('final_ptc', 'Final PTC', FALSE, 5, TRUE),
  ('judgment', 'Judgment', FALSE, 6, TRUE),
  ('ruling', 'Ruling', FALSE, 7, TRUE)
ON CONFLICT (name) DO UPDATE SET label = EXCLUDED.label, sort_order = EXCLUDED.sort_order, is_active = TRUE;

-- ============================================================
-- CASE NUMBER COUNTERS (atomic per type+year sequence)
-- ============================================================
CREATE TABLE IF NOT EXISTS case_number_counters (
  case_type_id INT NOT NULL REFERENCES case_categories(id) ON DELETE RESTRICT,
  year         INT NOT NULL,
  last_seq     INT NOT NULL DEFAULT 0,
  PRIMARY KEY (case_type_id, year)
);

-- ============================================================
-- CASES (the hub)
-- ============================================================
CREATE TABLE IF NOT EXISTS cases (
  id                      SERIAL PRIMARY KEY,
  case_number             VARCHAR(30)  NOT NULL UNIQUE,      -- e.g. CV-2026-001
  client_id               INT REFERENCES clients(id) ON DELETE RESTRICT,   -- optional at intake
  case_title              VARCHAR(255) NOT NULL,
  case_type_id            INT REFERENCES case_categories(id) ON DELETE RESTRICT,   -- no longer collected on the form; dormant
  status                  VARCHAR(50) NOT NULL DEFAULT 'mention' REFERENCES case_statuses(name),
  description             TEXT,                     -- narrative summary of the matter
  assigned_lawyer         INT REFERENCES users(id) ON DELETE SET NULL,
  opposing_party          VARCHAR(255),              -- Versus (Opponent)
  court                   VARCHAR(255),              -- Court Name
  region                  VARCHAR(255),              -- "In the {court} of Tanzania at {region}" on the printed Time Chart
  -- ---- Time Chart & Court Records fields (firm's existing paper tracking sheet) ----
  case_year               INT,
  parties                 TEXT,
  presiding_judge         VARCHAR(255),
  proceeding_type         VARCHAR(50),               -- Mention, 1st PTC, Mediation, Hearing, Final PTC, Judgment, Ruling
  proceeding_date         DATE,
  counsel_plaintiff       TEXT,
  counsel_defendant       TEXT,
  court_clerk             VARCHAR(255),
  last_court_order        TEXT,
  prayer_sought           TEXT,                      -- Current Prayer/Order/Direction Sought
  court_order_direction   TEXT,
  court_start_time        TIME,
  court_end_time          TIME,
  consultation_start_time TIME,
  consultation_end_time   TIME,
  record_date             DATE,
  recorded_by             VARCHAR(255),              -- Recorded By / Advocate Signature
  billing_amount          NUMERIC(12,2) NOT NULL DEFAULT 0,
  payment_status          VARCHAR(20)   NOT NULL DEFAULT 'unpaid'
                          CHECK (payment_status IN ('unpaid','partial','paid')),
  amount_paid             NUMERIC(12,2) NOT NULL DEFAULT 0,
  remarks                 TEXT,                      -- additional comments/observations
  claim_amount            NUMERIC(12,2),              -- Case Status Report: Claim Amount
  created_by              INT REFERENCES users(id) ON DELETE SET NULL,
  created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Idempotent migration for the Time Chart & Court Records fields, for
-- databases where the cases table already existed before they were added.
ALTER TABLE cases ADD COLUMN IF NOT EXISTS case_year               INT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS parties                 TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS presiding_judge         VARCHAR(255);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS proceeding_type         VARCHAR(50);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS proceeding_date         DATE;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS counsel_plaintiff       TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS counsel_defendant       TEXT;
ALTER TABLE cases ALTER COLUMN counsel_plaintiff TYPE TEXT;
ALTER TABLE cases ALTER COLUMN counsel_defendant TYPE TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS court_clerk             VARCHAR(255);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS last_court_order        TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS prayer_sought           TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS court_order_direction   TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS court_start_time        TIME;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS court_end_time          TIME;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS consultation_start_time TIME;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS consultation_end_time   TIME;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS record_date             DATE;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS recorded_by             VARCHAR(255);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS billing_amount          NUMERIC(12,2) NOT NULL DEFAULT 0;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS payment_status          VARCHAR(20) NOT NULL DEFAULT 'unpaid';
ALTER TABLE cases ADD COLUMN IF NOT EXISTS amount_paid             NUMERIC(12,2) NOT NULL DEFAULT 0;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS remarks                 TEXT;
ALTER TABLE cases ADD COLUMN IF NOT EXISTS claim_amount            NUMERIC(12,2);
ALTER TABLE cases ADD COLUMN IF NOT EXISTS region VARCHAR(255);
ALTER TABLE cases ALTER COLUMN client_id DROP NOT NULL;
ALTER TABLE cases ALTER COLUMN status SET DEFAULT 'mention';
ALTER TABLE cases ALTER COLUMN case_type_id DROP NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cases_client     ON cases(client_id);
CREATE INDEX IF NOT EXISTS idx_cases_status     ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_type       ON cases(case_type_id);
CREATE INDEX IF NOT EXISTS idx_cases_lawyer     ON cases(assigned_lawyer);
CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);
DROP TRIGGER IF EXISTS trg_cases_updated_at ON cases;
CREATE TRIGGER trg_cases_updated_at BEFORE UPDATE ON cases
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- HEARINGS (court dates — created only from inside a case)
-- ============================================================
CREATE TABLE IF NOT EXISTS hearings (
  id                       SERIAL PRIMARY KEY,
  case_id                  INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  hearing_date             TIMESTAMP NOT NULL,   -- the court date itself
  court                    VARCHAR(255),
  region                   VARCHAR(255),          -- "In the {court} of Tanzania at {region}" on the printed Time Chart
  purpose                  VARCHAR(255),          -- legacy, superseded by proceeding_type below
  outcome                  TEXT,                  -- legacy, superseded by court_order_direction below
  -- ---- Time Chart & Court Records fields, filled fresh at every court date ----
  presiding_judge          VARCHAR(255),
  proceeding_type          VARCHAR(50),           -- Mention, 1st PTC, Mediation, Hearing, Final PTC, Judgment, Ruling
  counsel_plaintiff        TEXT,
  counsel_defendant        TEXT,
  court_clerk              VARCHAR(255),
  last_court_order         TEXT,
  prayer_sought            TEXT,                  -- Current Prayer/Order/Direction Sought
  court_order_direction    TEXT,
  court_start_time         TIME,
  court_end_time           TIME,
  consultation_start_time  TIME,
  consultation_end_time    TIME,
  record_date              DATE,
  recorded_by              VARCHAR(255),          -- Recorded By / Advocate Signature
  next_court_date          TIMESTAMP,             -- date+time this matter was adjourned/scheduled to next
  created_by   INT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Idempotent migration for databases where the hearings table already existed
-- before the Time Chart & Court Records fields were added.
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS presiding_judge          VARCHAR(255);
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS proceeding_type          VARCHAR(50);
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS counsel_plaintiff        TEXT;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS counsel_defendant        TEXT;
ALTER TABLE hearings ALTER COLUMN counsel_plaintiff TYPE TEXT;
ALTER TABLE hearings ALTER COLUMN counsel_defendant TYPE TEXT;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS court_clerk              VARCHAR(255);
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS last_court_order         TEXT;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS prayer_sought            TEXT;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS court_order_direction    TEXT;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS court_start_time         TIME;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS court_end_time           TIME;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS consultation_start_time  TIME;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS consultation_end_time    TIME;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS record_date              DATE;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS recorded_by              VARCHAR(255);
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS next_court_date          TIMESTAMP;
ALTER TABLE hearings ADD COLUMN IF NOT EXISTS region                   VARCHAR(255);
ALTER TABLE hearings ALTER COLUMN next_court_date TYPE TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_hearings_case ON hearings(case_id);
CREATE INDEX IF NOT EXISTS idx_hearings_date ON hearings(hearing_date);
CREATE INDEX IF NOT EXISTS idx_hearings_next_court_date ON hearings(next_court_date);

-- ============================================================
-- APPOINTMENTS (client meetings — case optional, client required)
-- ============================================================
CREATE TABLE IF NOT EXISTS appointments (
  id               SERIAL PRIMARY KEY,
  case_id          INT REFERENCES cases(id) ON DELETE SET NULL,
  client_id        INT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  appointment_date TIMESTAMP NOT NULL,
  purpose          VARCHAR(255),
  consultation_fee NUMERIC(12,2),
  fee_paid         BOOLEAN NOT NULL DEFAULT FALSE,
  created_by       INT REFERENCES users(id) ON DELETE SET NULL,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_appointments_case   ON appointments(case_id);
CREATE INDEX IF NOT EXISTS idx_appointments_client ON appointments(client_id);
CREATE INDEX IF NOT EXISTS idx_appointments_date   ON appointments(appointment_date);

-- ============================================================
-- DOCUMENTS (physical files live under /uploads, not /public)
-- ============================================================
CREATE TABLE IF NOT EXISTS documents (
  id          SERIAL PRIMARY KEY,
  case_id     INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  category    VARCHAR(30) NOT NULL DEFAULT 'other'
              CHECK (category IN ('contract','court_order','evidence','judgment','correspondence','other')),
  filename    VARCHAR(255) NOT NULL,   -- original name shown to users
  file_path   VARCHAR(500) NOT NULL,   -- path relative to /uploads root
  file_size   INT,
  mime_type   VARCHAR(100),
  uploaded_by INT REFERENCES users(id) ON DELETE SET NULL,
  uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_documents_case     ON documents(case_id);
CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);

-- ============================================================
-- TASKS
-- ============================================================
CREATE TABLE IF NOT EXISTS tasks (
  id           SERIAL PRIMARY KEY,
  case_id      INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  title        VARCHAR(255) NOT NULL,
  due_date     DATE,
  assigned_to  INT REFERENCES users(id) ON DELETE SET NULL,
  status       VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done')),
  priority     VARCHAR(10) NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high')),
  created_by   INT REFERENCES users(id) ON DELETE SET NULL,
  completed_at TIMESTAMP,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tasks_case        ON tasks(case_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status      ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_due_date    ON tasks(due_date);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned_to ON tasks(assigned_to);
DROP TRIGGER IF EXISTS trg_tasks_updated_at ON tasks;
CREATE TRIGGER trg_tasks_updated_at BEFORE UPDATE ON tasks
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- EXPENSE CATEGORIES (editable lookup — not a hardcoded enum)
-- ============================================================
CREATE TABLE IF NOT EXISTS expense_categories (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(50)  NOT NULL UNIQUE,   -- slug used as the stored value, e.g. "filing_fees"
  label      VARCHAR(100) NOT NULL,          -- display text, e.g. "Filing Fees"
  is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO expense_categories (name, label) VALUES
  ('filing_fees', 'Filing Fees'),
  ('transport', 'Transport'),
  ('photocopying', 'Photocopying'),
  ('court_fees', 'Court Fees'),
  ('accommodation', 'Accommodation'),
  ('other', 'Other'),
  -- Office overhead categories — these expenses aren't tied to any one
  -- case (see expenses.case_id going nullable below), unlike the
  -- case-cost categories above.
  ('electricity', 'Electricity'),
  ('water', 'Water'),
  ('maintenance', 'Maintenance'),
  ('internet', 'Internet'),
  ('salaries', 'Salaries')
ON CONFLICT (name) DO NOTHING;

-- ============================================================
-- EXPENSES (money OUT)
-- ============================================================
CREATE TABLE IF NOT EXISTS expenses (
  id           SERIAL PRIMARY KEY,
  case_id      INT REFERENCES cases(id) ON DELETE CASCADE,   -- optional — office overhead (electricity, salaries, etc.) has no case
  description  VARCHAR(255) NOT NULL,
  category     VARCHAR(50) NOT NULL DEFAULT 'other' REFERENCES expense_categories(name),
  amount       NUMERIC(12,2) NOT NULL,
  expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_by   INT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE expenses ALTER COLUMN case_id DROP NOT NULL;
CREATE INDEX IF NOT EXISTS idx_expenses_case     ON expenses(case_id);
CREATE INDEX IF NOT EXISTS idx_expenses_date     ON expenses(expense_date);
CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(category);

-- ============================================================
-- INVOICES / INVOICE ITEMS / PAYMENTS (money IN — Billing & Payments)
-- ============================================================
CREATE TABLE IF NOT EXISTS invoices (
  id             SERIAL PRIMARY KEY,
  case_id        INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  invoice_number VARCHAR(30) NOT NULL UNIQUE,
  description    TEXT,
  total_amount   NUMERIC(12,2) NOT NULL DEFAULT 0,
  status         VARCHAR(20) NOT NULL DEFAULT 'unpaid' CHECK (status IN ('unpaid','partial','paid')),
  issued_date    DATE NOT NULL DEFAULT CURRENT_DATE,
  due_date       DATE,
  created_by     INT REFERENCES users(id) ON DELETE SET NULL,
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_invoices_case   ON invoices(case_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
DROP TRIGGER IF EXISTS trg_invoices_updated_at ON invoices;
CREATE TRIGGER trg_invoices_updated_at BEFORE UPDATE ON invoices
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE IF NOT EXISTS invoice_items (
  id          SERIAL PRIMARY KEY,
  invoice_id  INT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  description VARCHAR(255) NOT NULL,
  quantity    NUMERIC(10,2) NOT NULL DEFAULT 1,
  unit_price  NUMERIC(12,2) NOT NULL,
  line_total  NUMERIC(12,2) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice ON invoice_items(invoice_id);

CREATE TABLE IF NOT EXISTS payments (
  id             SERIAL PRIMARY KEY,
  invoice_id     INT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  case_id        INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE, -- denormalized, for timeline query
  amount         NUMERIC(12,2) NOT NULL,
  payment_date   DATE NOT NULL DEFAULT CURRENT_DATE,
  payment_method VARCHAR(50) DEFAULT 'cash',
  received_by    INT REFERENCES users(id) ON DELETE SET NULL,
  notes          TEXT,
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_payments_invoice ON payments(invoice_id);
CREATE INDEX IF NOT EXISTS idx_payments_case    ON payments(case_id);
CREATE INDEX IF NOT EXISTS idx_payments_date    ON payments(payment_date);

-- ============================================================
-- NOTES (manual only — never auto-generated)
-- ============================================================
CREATE TABLE IF NOT EXISTS notes (
  id         SERIAL PRIMARY KEY,
  case_id    INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_id  INT REFERENCES users(id) ON DELETE SET NULL,
  body       TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id);

-- ============================================================
-- SETTINGS (key-value office config)
-- ============================================================
CREATE TABLE IF NOT EXISTS settings (
  key        VARCHAR(100) PRIMARY KEY,
  value      TEXT,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO settings (key, value) VALUES
  ('office_name', 'Tanscar Attorneys'),
  ('office_address', ''),
  ('office_phone', ''),
  ('office_email', ''),
  ('currency', 'TSh'),
  ('max_login_attempts', '5'),
  ('lockout_minutes', '15')
ON CONFLICT (key) DO NOTHING;

-- db/schema.sql — Advocate Suite (Lawyer Case Management System)
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
  id              SERIAL PRIMARY KEY,
  case_number     VARCHAR(30)  NOT NULL UNIQUE,      -- e.g. CV-2026-001
  client_id       INT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
  case_title      VARCHAR(255) NOT NULL,
  case_type_id    INT NOT NULL REFERENCES case_categories(id) ON DELETE RESTRICT,
  status          VARCHAR(30) NOT NULL DEFAULT 'intake'
                  CHECK (status IN ('intake','active','filed','in_hearing','judgment',
                                     'closed_won','closed_lost','closed_settled')),
  description     TEXT,
  assigned_lawyer INT REFERENCES users(id) ON DELETE SET NULL,
  opposing_party  VARCHAR(255),
  court           VARCHAR(255),
  created_by      INT REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
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
  id           SERIAL PRIMARY KEY,
  case_id      INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  hearing_date TIMESTAMP NOT NULL,
  court        VARCHAR(255),
  purpose      VARCHAR(255),
  outcome      TEXT,
  created_by   INT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hearings_case ON hearings(case_id);
CREATE INDEX IF NOT EXISTS idx_hearings_date ON hearings(hearing_date);

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
-- EXPENSES (money OUT)
-- ============================================================
CREATE TABLE IF NOT EXISTS expenses (
  id           SERIAL PRIMARY KEY,
  case_id      INT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  description  VARCHAR(255) NOT NULL,
  category     VARCHAR(30) NOT NULL DEFAULT 'other'
               CHECK (category IN ('filing_fees','transport','photocopying','court_fees','accommodation','other')),
  amount       NUMERIC(12,2) NOT NULL,
  expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_by   INT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
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
  ('office_name', 'Advocate Suite'),
  ('office_address', ''),
  ('office_phone', ''),
  ('office_email', ''),
  ('currency', 'TSh'),
  ('max_login_attempts', '5'),
  ('lockout_minutes', '15')
ON CONFLICT (key) DO NOTHING;

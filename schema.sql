BEGIN;

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(40) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(100) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'user')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uidx ON users (LOWER(username));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uidx ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS categories (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(80) NOT NULL,
  kind VARCHAR(20) NOT NULL CHECK (kind IN ('income', 'expense')),
  slug VARCHAR(80),
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, name, kind),
  UNIQUE (user_id, slug)
);

CREATE TABLE IF NOT EXISTS financial_goals (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  goal_type VARCHAR(20) NOT NULL CHECK (goal_type IN ('ukt', 'emergency')),
  name VARCHAR(120) NOT NULL,
  target_amount BIGINT NOT NULL CHECK (target_amount > 0),
  monthly_target BIGINT NOT NULL DEFAULT 0 CHECK (monthly_target >= 0),
  due_date DATE,
  notes TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS debts (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  creditor_name VARCHAR(120) NOT NULL,
  original_amount BIGINT NOT NULL CHECK (original_amount > 0),
  interest_percent NUMERIC(7,4) NOT NULL DEFAULT 0 CHECK (interest_percent >= 0),
  monthly_target_min BIGINT NOT NULL DEFAULT 0 CHECK (monthly_target_min >= 0),
  monthly_target_max BIGINT NOT NULL DEFAULT 0 CHECK (monthly_target_max >= monthly_target_min),
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category_id BIGINT REFERENCES categories(id) ON DELETE RESTRICT,
  transaction_date DATE NOT NULL,
  transaction_month SMALLINT GENERATED ALWAYS AS (EXTRACT(MONTH FROM transaction_date)::SMALLINT) STORED,
  transaction_year SMALLINT GENERATED ALWAYS AS (EXTRACT(YEAR FROM transaction_date)::SMALLINT) STORED,
  transaction_type VARCHAR(20) NOT NULL CHECK (transaction_type IN ('income', 'expense', 'transfer')),
  amount BIGINT NOT NULL CHECK (amount > 0),
  description VARCHAR(180) NOT NULL,
  notes TEXT,
  source_type VARCHAR(30) NOT NULL DEFAULT 'manual' CHECK (source_type IN ('manual', 'debt_payment', 'goal_payment', 'goal_usage')),
  source_id BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS debt_payments (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  debt_id BIGINT NOT NULL REFERENCES debts(id) ON DELETE CASCADE,
  transaction_id BIGINT NOT NULL UNIQUE REFERENCES transactions(id) ON DELETE CASCADE,
  amount BIGINT NOT NULL CHECK (amount > 0),
  payment_date DATE NOT NULL,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS goal_transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  goal_id BIGINT NOT NULL REFERENCES financial_goals(id) ON DELETE CASCADE,
  transaction_id BIGINT UNIQUE REFERENCES transactions(id) ON DELETE CASCADE,
  entry_type VARCHAR(20) NOT NULL CHECK (entry_type IN ('contribution', 'withdrawal', 'payment', 'usage')),
  amount BIGINT NOT NULL CHECK (amount > 0),
  entry_date DATE NOT NULL,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS balance_adjustments (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount BIGINT NOT NULL CHECK (amount <> 0),
  reason VARCHAR(220) NOT NULL,
  adjustment_date DATE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(80) NOT NULL,
  entity_type VARCHAR(50) NOT NULL,
  entity_id BIGINT,
  before_data JSONB,
  after_data JSONB,
  ip_address INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS transactions_user_date_idx ON transactions(user_id, transaction_date DESC);
CREATE INDEX IF NOT EXISTS transactions_user_category_idx ON transactions(user_id, category_id);
CREATE INDEX IF NOT EXISTS transactions_user_type_idx ON transactions(user_id, transaction_type);
CREATE INDEX IF NOT EXISTS debts_user_idx ON debts(user_id);
CREATE INDEX IF NOT EXISTS debt_payments_debt_date_idx ON debt_payments(debt_id, payment_date DESC);
CREATE INDEX IF NOT EXISTS goals_user_type_idx ON financial_goals(user_id, goal_type);
CREATE INDEX IF NOT EXISTS goal_transactions_goal_date_idx ON goal_transactions(goal_id, entry_date DESC);
CREATE INDEX IF NOT EXISTS balance_adjustments_user_date_idx ON balance_adjustments(user_id, adjustment_date DESC);
CREATE INDEX IF NOT EXISTS audit_logs_user_created_idx ON audit_logs(user_id, created_at DESC);

COMMIT;

"""Repository layer for Anoryx-Sentinel persistence (F-003).

Each repository encapsulates data-access for one (or closely related) tables.
Repositories accept a SQLAlchemy Session or AsyncSession and use parameterized
queries only — no raw SQL string concatenation, no dynamic table/column names.
"""

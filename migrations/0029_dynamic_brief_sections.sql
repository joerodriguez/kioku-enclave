-- Additive brief presentation contract; NULL retains the legacy fixed groups.
-- Does not rewrite the frozen base schema or reconciliation activation receipts.
ALTER TABLE episode_final_briefs ADD COLUMN sections jsonb;
ALTER TABLE episode_final_briefs ADD CONSTRAINT episode_final_briefs_sections_array
    CHECK (sections IS NULL OR jsonb_typeof(sections) = 'array');

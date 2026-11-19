import {
  integer,
  jsonb,
  pgTable,
  serial,
  text,
  timestamp,
} from "drizzle-orm/pg-core";

export const scans = pgTable("scans", {
  id: serial("id").primaryKey(),
  url: text("url").notNull(),
  host: text("host").notNull(),
  finalUrl: text("final_url"),
  status: text("status").notNull().default("completed"), // completed | failed
  statusCode: integer("status_code"),
  grade: text("grade"),
  score: integer("score"),
  totalPoints: integer("total_points").notNull().default(0),
  findingsCount: integer("findings_count").notNull().default(0),
  counts: jsonb("counts").$type<{
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  }>(),
  tech: jsonb("tech").$type<string[]>().default([]),
  headers: jsonb("headers").$type<Record<string, string>>(),
  error: text("error"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const findings = pgTable("findings", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id")
    .notNull()
    .references(() => scans.id, { onDelete: "cascade" }),
  slug: text("slug").notNull(),
  severity: text("severity").notNull(), // critical | high | medium | low | info
  title: text("title").notNull(),
  category: text("category").notNull(),
  description: text("description").notNull().default(""),
  impact: text("impact").notNull().default(""),
  poc: text("poc").notNull().default(""),
  remediation: text("remediation").notNull().default(""),
  points: integer("points").notNull().default(0),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export type Scan = typeof scans.$inferSelect;
export type NewScan = typeof scans.$inferInsert;
export type Finding = typeof findings.$inferSelect;

// Loads Tools
require("dotenv").config();
const { Pool } = require("pg");

// Creates the Database connection pool
// A pool is a reusable set of database connections
const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

// NVD has had various CVSS (Common Vulnerability Scoring System) versions over the years.
// So some CVEs have different metrics we need to check for each version separately. It's how they themselves suggest how to handle this.
function getSeverity(cve) {
  const metrics = cve.metrics;

  if (metrics?.cvssMetricV40?.[0]?.cvssData?.baseSeverity) {
    return metrics.cvssMetricV40[0].cvssData.baseSeverity;
  }

  if (metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity) {
    return metrics.cvssMetricV31[0].cvssData.baseSeverity;
  }

  if (metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity) {
    return metrics.cvssMetricV30[0].cvssData.baseSeverity;
  }

  if (metrics?.cvssMetricV2?.[0]?.baseSeverity) {
    return metrics.cvssMetricV2[0].baseSeverity;
  }

  return "UNKNOWN";
}

// Retrieve the English description of the CVE
function getEnglishDescription(cve) {
  const descriptions = cve.descriptions || [];
  const englishDescription = descriptions.find((desc) => desc.lang === "en");

  return englishDescription?.value || "No description available.";
}

// Main Function
async function importCVEs() {
    // API URL with Query
  const url =
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50";

  console.log("Fetching CVEs from NVD...");

  // Calling the API and Response Handling
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`NVD API request failed: ${response.status}`);
  }

  const data = await response.json(); // Converts Response to JSON
  const vulnerabilities = data.vulnerabilities || [];

  console.log(`Fetched ${vulnerabilities.length} CVEs.`);

  // Looping through each CVE
  for (const item of vulnerabilities) {
    const cve = item.cve;

    // Extracting the fields we need
    const cveId = cve.id;
    const description = getEnglishDescription(cve);
    const severity = getSeverity(cve);
    const publishedDate = cve.published;

    // Inserts extracted row values into 'vulnerabilities' table with Parameterized Querying (protects from SQL injection)
    await pool.query(
      `
      INSERT INTO vulnerabilities (cve_id, description, severity, published_date)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (cve_id) DO NOTHING;
      `,
      [cveId, description, severity, publishedDate],
    );

    console.log(`Inserted: ${cveId} | ${severity}`);
  }

  console.log("Done importing CVEs.");
}

// Running the script
importCVEs()
    // Catches errors
    .catch((error) => {
        console.error("Import failed:", error.message);
    })
    // Closes the database connection
    .finally(async () => {
        await pool.end();
    });

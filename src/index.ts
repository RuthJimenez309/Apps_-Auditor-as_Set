import { IAMSimulator } from "./iam.js";
import { SecurityScanner } from "./securityScanner.js";

function runSecurityAuditPipeline() {
  console.log("=== INICIANDO PIPELINE DE AUDITORÍA DE SEGURIDAD (DÍA 28) ===");

  // 1. Inicializar el motor IAM
  const iam = new IAMSimulator();

  // 2. Emitir un token válido para simular acceso legítimo
  const adminToken = iam.issueToken({
    userId: "123e4567-e89b-12d3-a456-426614174000",
    email: "admin@empresa.com",
    role: "admin",
  });

  // 3. Inicializar el Escáner de Seguridad
  const scanner = new SecurityScanner(iam);

  console.log("\n[!] Ejecutando pruebas automatizadas contra endpoints...");

  // Prueba A: Simular ataque IDOR / BOLA enviando un token vacío o inválido
  scanner.scanIDOR("", "financial_reports_2026");

  // Prueba B: Simular ataque de inyección SQL en un campo de entrada
  scanner.scanInjection("SELECT * FROM users; --");

  // 4. Consolidar evidencias y generar reporte técnico de GRC
  const findings = scanner.getReportSummary();

  console.log("\n=== REPORTE TÉCNICO DE RIESGOS GENERADO ===");
  if (findings.length === 0) {
    console.log(
      "✔ No se detectaron vulnerabilidades críticas en el ecosistema.",
    );
  } else {
    findings.forEach((finding, index) => {
      console.log(`\nHallazgo #${index + 1}: [Severidad: ${finding.severity}]`);
      console.log(`Tipo: ${finding.vulnerabilityType}`);
      console.log(`Descripción: ${finding.description}`);
      console.log(`Evidencia técnica: ${finding.evidence}`);
    });
  }
  console.log("\n=== PIPELINE FINALIZADO CON ÉXITO ===");
}

runSecurityAuditPipeline();

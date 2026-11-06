    import { IAMSimulator } from "./iam.js";

    export interface VulnerabilityResult {
    vulnerabilityType: string;
    severity: "High" | "Medium" | "Low";
    description: string;
    evidence: string;
    }

    export class SecurityScanner {
    private iam: IAMSimulator;
    private findings: VulnerabilityResult[] = [];

    constructor(iamInstance: IAMSimulator) {
        this.iam = iamInstance;
    }

    scanIDOR(token: string, targetResourceId: string): void {
        const isAuthorized = this.iam.authorize(token, "financial_reports", "read");
        if (!isAuthorized) {
        this.findings.push({
            vulnerabilityType: "Broken Object Level Authorization (BOLA)",
            severity: "High",
            description: "Se detectó acceso no autorizado a un identificador de recurso directo sin validación de pertenencia.",
            evidence: `Token evaluado intentó leer el recurso: ${targetResourceId}`
        });
        }
    }

    scanInjection(input: string): void {
        const sqlPattern = /('|--|UNION|SELECT|INSERT|DELETE)/i;
        if (sqlPattern.test(input)) {
        this.findings.push({
            vulnerabilityType: "SQL Injection emulada",
            severity: "High",
            description: "Caracteres sospechosos detectados en el payload de entrada sin sanitización activa.",
            evidence: `Payload recibido: ${input}`
        });
        }
    }

    getReportSummary() {
        return this.findings;
    }
    }

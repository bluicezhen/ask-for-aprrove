export type RiskSignal = 'file-or-permission-change' | 'dynamic-command-execution' | 'privilege-or-system-change' | 'credential-access' | 'external-write' | 'destructive-version-control' | 'cloud-resource-change';
export interface RiskResult {
    readonly safe: boolean;
    readonly signals: readonly RiskSignal[];
}
export declare function detectFixedHighRisk(command: string, segments: readonly (readonly string[])[]): RiskResult;
//# sourceMappingURL=risk.d.ts.map
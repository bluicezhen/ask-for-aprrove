const words = new Set(['rm', 'cp', 'mv', 'chmod', 'chown', 'mkdir', 'touch', 'eval', 'exec', 'bash', 'sh', 'python', 'python3', 'xargs', 'sudo', 'apt', 'apt-get', 'yum', 'dnf', 'systemctl', 'shutdown', 'env', 'printenv', 'scp', 'rsync']);
const cloud = new Set(['delete', 'remove', 'release', 'terminate', 'stop', 'reboot', 'modify', 'update', 'create', 'destroy', 'purge']);
const clouds = new Set(['aliyun', 'aws', 'az', 'gcloud', 'arkcli']);
export function detectFixedHighRisk(command, segments) {
    const signals = new Set();
    for (const segment of segments) {
        const executable = segment[0]?.toLowerCase();
        if (executable && words.has(executable)) {
            if (['rm', 'cp', 'mv', 'chmod', 'chown', 'mkdir', 'touch'].includes(executable))
                signals.add('file-or-permission-change');
            else if (['eval', 'exec', 'bash', 'sh', 'python', 'python3', 'xargs'].includes(executable))
                signals.add('dynamic-command-execution');
            else if (['sudo', 'apt', 'apt-get', 'yum', 'dnf', 'systemctl', 'shutdown'].includes(executable))
                signals.add('privilege-or-system-change');
            else if (['env', 'printenv'].includes(executable))
                signals.add('credential-access');
            else
                signals.add('external-write');
        }
        if (segment.some(token => token.includes('.env') || token.includes('.ssh')))
            signals.add('credential-access');
        if (executable === 'curl' && segment.some(token => token.toLowerCase() === '-x' || token.toLowerCase() === '--request') && segment.some(token => token.toUpperCase() === 'POST' || token.toUpperCase() === 'PUT' || token.toUpperCase() === 'DELETE'))
            signals.add('external-write');
        if (executable === 'git' && ['push', 'commit', 'reset', 'clean'].includes((segment[1] ?? '').toLowerCase()))
            signals.add('destructive-version-control');
        if (executable && clouds.has(executable) && segment.slice(1).some(token => {
            const normalized = token.toLowerCase().replace(/[^a-z]/g, '');
            return [...cloud].some(action => normalized.startsWith(action));
        }))
            signals.add('cloud-resource-change');
    }
    return { safe: signals.size === 0, signals: [...signals] };
}

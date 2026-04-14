// Helper function to create initial module status
export function createModuleStatus(name, displayName) {
    return {
        name,
        display_name: displayName,
        status: "pending",
        progress: 0,
        result_count: 0,
    };
}
// Helper function to create empty scan session
export function createEmptyScanSession(systemInfo) {
    return {
        id: systemInfo.scan_id,
        system_info: systemInfo,
        modules: [],
        results: {
            apps: [],
            browsers: [],
            keywords: [],
            hashes: [],
            media: [],
        },
        started_at: systemInfo.scan_timestamp,
        completed_at: null,
    };
}
// Helper function to get module by name
export function getModule(session, name) {
    return session.modules.find(m => m.name === name);
}
// Helper function to check if all modules are complete
export function isSessionComplete(session) {
    return session.modules.every(m => m.status === "complete" || m.status === "error");
}
// Helper function to count running modules
export function getRunningModulesCount(session) {
    return session.modules.filter(m => m.status === "running").length;
}
// Helper function to get total result count
export function getTotalResultCount(session) {
    return (session.results.apps.length +
        session.results.browsers.length +
        session.results.keywords.length +
        session.results.hashes.length +
        session.results.media.length);
}
// Helper function to get completion percentage
export function getSessionProgress(session) {
    if (session.modules.length === 0)
        return 0;
    const totalProgress = session.modules.reduce((sum, module) => {
        if (module.status === "complete")
            return sum + 100;
        if (module.status === "running")
            return sum + (module.progress || 0);
        return sum;
    }, 0);
    return Math.round(totalProgress / session.modules.length);
}

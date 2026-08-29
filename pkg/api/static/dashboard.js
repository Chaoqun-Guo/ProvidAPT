// Dashboard refresh loop.

async function refresh() {
  const now = new Date();
  document.getElementById('refreshInfo').textContent = 'Updated: ' + now.toLocaleTimeString();
  await Promise.all([loadStatus(), loadHealth(), loadControlOverview(), loadSupportBundles(), loadBackups(), loadUpgradeStatus(), loadPolicies(), loadAlertWorkflow(), loadDeliveries(), loadCompliance(), loadGroundTruth()]);
  loadOperationsSummary();
  classifyDashboardButtons();
  normalizeDashboardPanels();
  scheduleDashboardMasonry();
}

window.addEventListener('resize', scheduleDashboardMasonry);

migrateDashboardLayoutStorage();
initializePanelLayout();
installInteractionFeedback();
installProtectedAPILinkHandler();
refresh();
setInterval(refresh, 5000);

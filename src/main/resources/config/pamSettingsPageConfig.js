/**
 * Adds the "Platforms", "Password Policies", "Password Rotation",
 * "Checkouts" and "PAM Settings" tabs to the settings panel for
 * administrators, the "Approvals" tab for approvers, and, when the HA module
 * runs, the "High Availability" tab for those who may see the status of the
 * servers, by decorating userPageService.getSettingsPages().
 * The tab contents are injected into settings.html by
 * templates/settingsPamTab.html.
 */
angular.module('guacPam').config(['$provide', function pamSettingsPageConfig($provide) {

    $provide.decorator('userPageService', ['$delegate', '$injector',
            function decorateUserPageService($delegate, $injector) {

        var getSettingsPages = $delegate.getSettingsPages;

        $delegate.getSettingsPages = function getSettingsPagesWithPam() {
            return getSettingsPages.apply(this, arguments)
            .then(function addPamPage(pages) {

                var $q             = $injector.get('$q');
                var PageDefinition = $injector.get('PageDefinition');
                var pamService     = $injector.get('pamService');
                var pamHaService   = $injector.get('pamHaService');

                // The HA module's status is only looked for where it runs
                var access = pamService.getAccess().then(angular.identity, function accessFailed() {
                    return {};
                });
                var haDataSource = access.then(function findHaDataSource(access) {
                    return access.ha ? pamHaService.findDataSource() : null;
                });

                return $q.all([access, haDataSource]).then(function accessRetrieved(results) {
                    var access = results[0];
                    var haDataSource = results[1];
                    if (access.administrator) {
                        pages.push(new PageDefinition({
                            name : 'PAM.TAB_PLATFORMS',
                            url  : '/settings/pam-platforms'
                        }));
                        pages.push(new PageDefinition({
                            name : 'PAM.TAB_PASSWORD_POLICIES',
                            url  : '/settings/pam-password-policies'
                        }));
                        pages.push(new PageDefinition({
                            name      : 'PAM.TAB_ROTATION',
                            url       : '/settings/pam-rotation',
                            className : 'pam-rotation-page'
                        }));
                        pages.push(new PageDefinition({
                            name : 'PAM.TAB_CHECKOUTS',
                            url  : '/settings/pam-checkouts'
                        }));
                    }
                    if (access.approver)
                        pages.push(new PageDefinition({
                            name      : 'PAM.TAB_APPROVALS',
                            url       : '/settings/pam-approvals',
                            className : 'pam-approvals-page'
                        }));
                    if (access.administrator)
                        pages.push(new PageDefinition({
                            name : 'PAM.TAB_SETTINGS',
                            url  : '/settings/pam-settings'
                        }));
                    if (haDataSource)
                        pages.push(new PageDefinition({
                            name : 'PAM_HA.TAB_HA',
                            url  : '/settings/' + encodeURIComponent(haDataSource) + '/pam-ha'
                        }));
                    return pages;
                });

            });
        };

        return $delegate;

    }]);

}]);

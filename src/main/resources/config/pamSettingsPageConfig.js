/**
 * Adds the "Platforms", "Password Rotation" and "Checkouts" tabs to the
 * settings panel for administrators, and the "Approvals" tab for approvers, by
 * decorating userPageService.getSettingsPages().
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

                var PageDefinition = $injector.get('PageDefinition');
                var pamService     = $injector.get('pamService');

                return pamService.getAccess().then(function accessRetrieved(access) {
                    if (access.administrator) {
                        pages.push(new PageDefinition({
                            name : 'PAM.TAB_PLATFORMS',
                            url  : '/settings/pam-platforms'
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
                    return pages;
                }, function accessFailed() {
                    return pages;
                });

            });
        };

        return $delegate;

    }]);

}]);

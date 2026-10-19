/**
 * Always shows the home screen after login. Guacamole normally sends a user
 * with access to a single connection straight into it; users instead choose
 * it on the home screen, like everyone else (and connections needing a
 * request show their dialog from there).
 */
angular.module('guacPam').config(['$provide', function pamHomePageConfig($provide) {

    $provide.decorator('userPageService', ['$delegate', '$injector',
            function decorateHomePage($delegate, $injector) {

        var getHomePage = $delegate.getHomePage;

        $delegate.getHomePage = function getHomePageWithoutClient() {

            var PageDefinition = $injector.get('PageDefinition');

            return getHomePage.apply(this, arguments).then(function homePageRetrieved(page) {
                if (page && page.url && page.url.indexOf('/client/') === 0)
                    return new PageDefinition({ name : 'USER_MENU.ACTION_NAVIGATE_HOME', url : '/' });
                return page;
            });

        };

        return $delegate;

    }]);

}]);

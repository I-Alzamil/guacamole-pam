/**
 * The import page of platforms, and its file format help, laid out as
 * Guacamole's own connection import ("/import/:dataSource/connection").
 */
angular.module('guacPam').config(['$routeProvider', function pamImportRouteConfig($routeProvider) {

    // As Guacamole's own routes: picks up a token given in the URL
    var updateCurrentToken = ['$injector', function updateCurrentToken($injector) {
        var $location = $injector.get('$location');
        return $injector.get('authenticationService').updateCurrentToken($location.search());
    }];

    $routeProvider
        .when('/import/pam/platforms', {
            title         : 'APP.NAME',
            bodyClassName : 'settings',
            templateUrl   : 'app/ext/pam/templates/pamPlatformImport.html',
            controller    : 'pamPlatformImportController',
            resolve       : { updateCurrentToken : updateCurrentToken }
        })
        .when('/import/pam/platforms/file-format-help', {
            title         : 'APP.NAME',
            bodyClassName : 'settings',
            templateUrl   : 'app/ext/pam/templates/pamPlatformImportHelp.html',
            resolve       : { updateCurrentToken : updateCurrentToken }
        });

}]);

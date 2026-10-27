/**
 * The status of the servers sharing the database, from the HA module
 * ("api/session/ext/DATA_SOURCE/pam-ha/status"), of the first data source it
 * shares whose administrator the current user is. Without the HA module,
 * there is none.
 */
angular.module('guacPam').factory('pamHaService', ['$injector', function pamHaService($injector) {

    var $q                    = $injector.get('$q');
    var authenticationService = $injector.get('authenticationService');

    var service = {};

    /**
     * The data source whose status the current user may see, by token, so
     * it is looked for once per login.
     */
    var dataSources = {};

    service.getStatus = function getStatus(dataSource, check) {
        return authenticationService.request({
            method : 'GET',
            url    : 'api/session/ext/' + encodeURIComponent(dataSource) + '/pam-ha/status',
            params : check ? { check : true } : {}
        });
    };

    /**
     * Resolves with the data source to show the status of, or null if the
     * current user may see none, as when the HA module is off.
     */
    service.findDataSource = function findDataSource() {

        var token = authenticationService.getCurrentToken();
        if (!dataSources[token]) {
            dataSources[token] = authenticationService.getAvailableDataSources().reduce(function next(found, dataSource) {
                return found.then(function checked(result) {
                    return result || service.getStatus(dataSource).then(function statusRead() {
                        return dataSource;
                    }, function statusRefused(error) {
                        // Refused: not theirs to see. Anything else, such as
                        // a server restarting, is looked for again later
                        if (error && error.type === 'PERMISSION_DENIED')
                            return null;
                        return $q.reject(error);
                    });
                });
            }, $q.resolve(null))['catch'](function notFound() {
                delete dataSources[token];
                return null;
            });
        }
        return dataSources[token];

    };

    return service;

}]);

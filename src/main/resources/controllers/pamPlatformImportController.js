/**
 * The import page of platforms: reads a file exported from the Platforms
 * tab, and imports its platforms, all or none, as Guacamole's own
 * connection import does for connections.
 */
angular.module('guacPam').controller('pamPlatformImportController', ['$scope', '$injector',
        function pamPlatformImportController($scope, $injector) {

    // Required services
    var $location        = $injector.get('$location');
    var $window          = $injector.get('$window');
    var guacNotification = $injector.get('guacNotification');
    var pamService       = $injector.get('pamService');

    /**
     * Format and version of the files Export writes.
     */
    var EXPORT_FORMAT = 'guacamole-pam-platforms';
    var EXPORT_VERSION = 1;

    var SETTINGS_URL = '/settings/pam-platforms';

    /**
     * Name of the file read, and its platforms, or null.
     */
    $scope.fileName = null;
    $scope.platforms = null;

    /**
     * Whether platforms named as existing ones update them, rather than
     * refusing the import.
     */
    $scope.options = { update : false };

    $scope.processing = false;

    /**
     * Platforms refusing the last import: row number, name, type and why.
     */
    $scope.errors = [];

    var showError = function showError(key, variables) {
        guacNotification.showStatus({
            className : 'error',
            title     : 'IMPORT.DIALOG_HEADER_ERROR',
            text      : { key : key, variables : variables },
            actions   : [{
                name     : 'IMPORT.ACTION_ACKNOWLEDGE',
                callback : function acknowledge() {
                    guacNotification.showStatus(false);
                }
            }]
        });
    };

    /**
     * The platforms of an exported file, given its text, or null after
     * showing why there are none.
     */
    var readExport = function readExport(text) {

        if (!text || !text.trim()) {
            showError('IMPORT.ERROR_EMPTY_FILE');
            return null;
        }

        var data;
        try {
            data = JSON.parse(text);
        }
        catch (e) {
            showError('IMPORT.ERROR_PARSE_FAILURE_JSON', { ERROR : e.message });
            return null;
        }

        // A bare list of platforms is read as well
        if (!angular.isArray(data)) {
            if (!angular.isObject(data) || data.format !== EXPORT_FORMAT || !angular.isArray(data.platforms)) {
                showError('PAM_PLATFORM_IMPORT.ERROR_NOT_PLATFORMS');
                return null;
            }
            if (data.version > EXPORT_VERSION) {
                showError('PAM_PLATFORM_IMPORT.ERROR_NEWER_VERSION');
                return null;
            }
            data = data.platforms;
        }

        if (!data.length) {
            showError('IMPORT.ERROR_EMPTY_FILE');
            return null;
        }

        return data;

    };

    /**
     * Reads the file chosen or dropped (guac-upload, guac-drop).
     */
    $scope.handleFiles = function handleFiles(files) {

        var file = files[0];
        var reader = new $window.FileReader();

        reader.onloadend = function fileRead() {
            $scope.$apply(function showFile() {
                var platforms = reader.error ? null : readExport(reader.result);
                if (reader.error)
                    showError('PAM_PLATFORM_IMPORT.ERROR_READ');
                $scope.platforms = platforms;
                $scope.fileName = platforms ? file.name : null;
                $scope.errors = [];
            });
        };

        reader.readAsText(file);

    };

    $scope.clear = function clear() {
        $scope.fileName = $scope.platforms = null;
        $scope.errors = [];
    };

    $scope.cancel = function cancel() {
        $location.url(SETTINGS_URL);
    };

    $scope['import'] = function importPlatforms() {

        $scope.processing = true;
        $scope.errors = [];

        pamService.importPlatforms($scope.platforms, $scope.options.update).then(function imported(report) {

            if (!report.imported) {
                var errors = [];
                angular.forEach(report.results, function addError(result, index) {
                    if (result.outcome === 'INVALID')
                        errors.push({
                            rowNumber : index + 1,
                            name      : result.name,
                            type      : ($scope.platforms[index] || {}).type,
                            message   : result.message
                        });
                });
                $scope.errors = errors;
                return;
            }

            var counts = { CREATED : 0, UPDATED : 0 };
            angular.forEach(report.results, function countResult(result) {
                counts[result.outcome] = (counts[result.outcome] || 0) + 1;
            });

            guacNotification.showStatus({
                title   : 'IMPORT.DIALOG_HEADER_SUCCESS',
                text    : { key : 'PAM_PLATFORM_IMPORT.INFO_PLATFORMS_IMPORTED_SUCCESS', variables : counts },
                actions : [{
                    name     : 'IMPORT.ACTION_ACKNOWLEDGE',
                    callback : function acknowledge() {
                        guacNotification.showStatus(false);
                        $location.url(SETTINGS_URL);
                    }
                }]
            });

        }, guacNotification.SHOW_REQUEST_ERROR)
        ['finally'](function importDone() {
            $scope.processing = false;
        });

    };

}]);

/**
 * Registers the field types of this extension:
 *
 * PAM_PLATFORM - drop-down of platforms, for the "pam-platform" connection
 *                attribute.
 * PAM_SCRIPT   - sequence script editor with live validation, for the
 *                settings of SSH platforms.
 */
angular.module('guacPam').config(['formServiceProvider', function pamFieldTypeConfig(formServiceProvider) {

    formServiceProvider.registerFieldType('PAM_PLATFORM', {
        module      : 'guacPam',
        controller  : 'pamPlatformFieldController',
        templateUrl : 'app/ext/pam/templates/pamPlatformField.html'
    });

    formServiceProvider.registerFieldType('PAM_SCRIPT', {
        module      : 'guacPam',
        controller  : 'pamScriptFieldController',
        templateUrl : 'app/ext/pam/templates/pamScriptField.html'
    });

}]);

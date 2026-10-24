/**
 * Registers the field types of this extension:
 *
 * PAM_PLATFORM        - searchable picker of platforms (pamPlatformPicker),
 *                       for the "pam-platform" connection attribute.
 * PAM_PASSWORD_POLICY - drop-down of password policies, for the policy of
 *                       platforms and the "pam-password-policy" connection
 *                       attribute.
 * PAM_SCRIPT   - sequence script editor with live validation, for the
 *                settings of SSH platforms.
 */
angular.module('guacPam').config(['formServiceProvider', function pamFieldTypeConfig(formServiceProvider) {

    formServiceProvider.registerFieldType('PAM_PLATFORM', {
        templateUrl : 'app/ext/pam/templates/pamPlatformField.html'
    });

    formServiceProvider.registerFieldType('PAM_PASSWORD_POLICY', {
        module      : 'guacPam',
        controller  : 'pamPasswordPolicyFieldController',
        templateUrl : 'app/ext/pam/templates/pamPasswordPolicyField.html'
    });

    formServiceProvider.registerFieldType('PAM_SCRIPT', {
        module      : 'guacPam',
        controller  : 'pamScriptFieldController',
        templateUrl : 'app/ext/pam/templates/pamScriptField.html'
    });

}]);

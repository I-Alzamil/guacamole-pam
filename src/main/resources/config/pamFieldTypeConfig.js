/**
 * Registers the field types of this extension:
 *
 * PAM_PLATFORM        - searchable picker of platforms (pamPlatformPicker),
 *                       for the "pam-platform" connection attribute.
 * PAM_PASSWORD_POLICY - drop-down of password policies, for the policy of
 *                       platforms and the "pam-password-policy" connection
 *                       attribute.
 * PAM_ROTATION_INTERVAL - hours between rotations, shown only while they
 *                       are periodic, for the policy of platforms and the
 *                       "pam-rotation-interval" connection attribute.
 * PAM_SCRIPT   - sequence script editor with live validation, for the
 *                settings of SSH platforms.
 * PAM_ENUM     - drop-down of options in the order the server lists them
 *                (Guacamole's own ENUM sorts them), so insecure ones come
 *                last.
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

    formServiceProvider.registerFieldType('PAM_ROTATION_INTERVAL', {
        module      : 'guacPam',
        controller  : 'pamRotationIntervalFieldController',
        templateUrl : 'app/ext/pam/templates/pamRotationIntervalField.html'
    });

    formServiceProvider.registerFieldType('PAM_ENUM', {
        module      : 'form',
        controller  : 'selectFieldController',
        templateUrl : 'app/ext/pam/templates/pamEnumField.html'
    });

    formServiceProvider.registerFieldType('PAM_SCRIPT', {
        module      : 'guacPam',
        controller  : 'pamScriptFieldController',
        templateUrl : 'app/ext/pam/templates/pamScriptField.html'
    });

}]);

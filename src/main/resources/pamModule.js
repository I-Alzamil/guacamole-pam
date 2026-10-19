/**
 * Module for the privileged access management extension: sequence profiles,
 * per-connection password rotation settings, and the "Password Rotation"
 * settings tab.
 */
angular.module('guacPam', []);

// Ensure the guacPam module is loaded along with the rest of the app
angular.module('index').requires.push('guacPam');

<?php
/*Plugin Name: WP JWT Auth
Description: Este plugin permite criar um token valido para requisições na API REST do Wordpress.
Author: Votan Ruchel
Author URI: https://www.votan.dev/
Version: 1.0

*/

include('jwt.php');

function wv_api_init(){
    $namespace = 'authenticationjwt/v1';
    register_rest_route($namespace,'/login',array(
        'methods' => 'POST',
        'callback' => 'wv_api_ep_login'
    ));
    register_rest_route($namespace, '/validate', array(
        'methods' => 'GET',
        'callback' => 'wv_api_ep_validate'
    ));
    add_filter('rest_pre_dispatch', 'wv_rest_pre_dispatch', 10, 3);
}
function wv_rest_pre_dispatch($url, $server, $req){
    $params = $req->get_params();
    if(!empty($params['jwt'])){
        $jwt = new JWT();
        $info = $jwt->validate($params['jwt']);

        if ($info && !empty($info->id)) {
            wp_set_current_user($info->id);
        }
    }
}

function wv_api_ep_validate($req){
    $array = array('valid' => false);
    $params = $req->get_params();
    if(!empty($params['jwt'])){
        $jwt = new JWT();
        $info = $jwt->validate($params['jwt']);

        if($info && !empty($info->id)){
            $array['valid'] = true;
        }
    }
    return $array;
}

function wv_api_ep_login($req){
    $array = array('logged' => false);
    $params = $req->get_params();
    $result = wp_signon(array(
        'user_login' => $params['username'],
        'user_password' => $params['password']
    ));
    if (is_wp_error($result)) {
        echo $result->get_error_message();
    }
    if(isset($result->data)){
        $jwt = new JWT();
        $token = $jwt->create(array('id' => $result->data->ID));
        $array['logged'] = true;
        $array['token'] = $token;
    }else{
        
    }
    return $array;
}

add_action('rest_api_init','wv_api_init');
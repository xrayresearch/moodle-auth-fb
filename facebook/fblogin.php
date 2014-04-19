<?php

/**
 * Date: Aug 24, 2013
 * programmer: Shani Mahadeva <satyashani@gmail.com>
 * Description:
 * */

global $CFG, $SESSION;
$redirect = empty($SESSION->wantsurl)?$CFG->wwwroot:$SESSION->wantsurl;
$conf = get_config("auth/facebook");
?>
<script src="http://connect.facebook.net/en_US/all.js"></script>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
<div id="fb-root" style="display: inline;">
<a class='fb-login-button' scope="email" onlogin="afterLogin" id="fblogin" href="#" style="display: none;margin: 0px 10px; top:8px;">Login</a>
</div>
<script>
	FB.init({
	  appId      : '<?php echo $conf->appid;?>', // App ID
	  channelUrl : '<?php echo $conf->channelurl;?>', // Channel File
	  status     : true, // check login status
	  cookie     : true, // enable cookies to allow the server to access the session
	  xfbml      : true  // parse XFBML
	});
	
	$(document).ready(function(){
		$("input#loginbtn").after($("div#fb-root"));
		$("a#fblogin").show();
	})

	function afterLogin(response){
		if (response.status === 'connected') {
			$.post("./index.php",{
					'fblogin':true
				},function(data){
					window.location.href = '<?php echo $redirect;?>';
				}
			)
			$("#fblogin").hide();
		} else if (response.status === 'not_authorized') {
			alert("not authorized by user");
			FB.login();
		} else {

		}
	}
</script>
</body>
</html>
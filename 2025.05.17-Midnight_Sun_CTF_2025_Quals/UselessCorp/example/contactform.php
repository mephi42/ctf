<?php

/**
 * This example shows how to handle a simple contact form safely.
 */

$msg = '';
//Don't run this unless we're handling a form submission
if (array_key_exists('email', $_POST)) {
    date_default_timezone_set('Etc/UTC');

    require 'vendor/phpmailer/phpmailer/class.phpmailer.php';
    require 'vendor/phpmailer/phpmailer/class.smtp.php';

    PHPMailer::$validator = 'noregex';  // XXX

    //Create a new PHPMailer instance
    $mail = new PHPMailer();
    //Send using SMTP to localhost (faster and safer than using mail()) – requires a local mail server
    //See other examples for how to use a remote server such as gmail
    //XXX $mail->isSMTP();
    $mail->Host = 'localhost';
    $mail->Port = 25;

    //Use a fixed address in your own domain as the from address
    //**DO NOT** use the submitter's address here as it will be forgery
    //and will cause your messages to fail SPF checks
    //XXX $mail->setFrom('from@example.com', 'First Last');
    if (!$mail->setFrom($_POST['email'], $_POST['name'])) { $msg = $mail->ErrorInfo; goto a; }
    //Choose who the message should be sent to
    //You don't have to use a <select> like in this example, you can simply use a fixed address
    //the important thing is *not* to trust an email address submitted from the form directly,
    //as an attacker can substitute their own and try to use your form to send spam
    $addresses = [
        'sales' => 'sales@example.com',
        'support' => 'support@example.com',
        'accounts' => 'accounts@example.com',
    ];
    //Validate address selection before trying to use it
    if (array_key_exists('dept', $_POST) && array_key_exists($_POST['dept'], $addresses)) {
        $mail->addAddress($addresses[$_POST['dept']]);
    } else {
        //Fall back to a fixed address if dept selection is invalid or missing
        $mail->addAddress('support@example.com');
    }
    //Put the submitter's address in a reply-to header
    //This will fail if the address provided is invalid,
    //in which case we should ignore the whole request
    if ($mail->addReplyTo($_POST['email'], $_POST['name'])) {
        $mail->Subject = 'PHPMailer contact form';
        //Keep it simple - don't use HTML
        $mail->isHTML(false);
        //Build a simple message body
        $mail->Body = <<<EOT
Email: {$_POST['email']}
Name: {$_POST['name']}
Message: {$_POST['message']}
EOT;
        //Send the message, check for errors
        if (!$mail->send()) {
            //The reason for failing to send will be in $mail->ErrorInfo
            //but it's unsafe to display errors directly to users - process the error, log it on your server.
            //$msg = 'Sorry, something went wrong. Please try again later.';
            $msg = 'Sorry, something went wrong. Please try again later.' . $mail->ErrorInfo;
        } else {
            $msg = 'Message sent! Thanks for contacting us.';
        }
    } else {
        $msg = 'Invalid email address, message ignored.';
    }
}
a:
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact form</title>
</head>
<body>
<h1>Contact us</h1>
<?php if (!empty($msg)) {
    echo "<h2>$msg</h2>";
} ?>
<form method="POST">
    <label for="name">Name: <input type="text" name="name" id="name"></label><br>
    <label for="email">Email address: <input type="email" name="email" id="email"></label><br>
    <label for="message">Message: <textarea name="message" id="message" rows="8" cols="20"></textarea></label><br>
    <label for="dept">Send query to department:</label>
    <select name="dept" id="dept">
        <option value="sales">Sales</option>
        <option value="support" selected>Technical support</option>
        <option value="accounts">Accounts</option>
    </select><br>
    <input type="submit" value="Send">
</form>
</body>
</html>
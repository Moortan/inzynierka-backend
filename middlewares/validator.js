module.exports = {
    isAlphaNumericOnly : input => {
        let letterNumberRegex = /^[a-zA-Z0-9 .-]+$/;
        return input.match(letterNumberRegex)
    },
    isLongEnough: input => {
        return input.length >= 4;
    },
    isGoodPassword: (pass, username, email) => {

        //8 to 64 character password requiring at least 3 out 4 (uppercase and lowercase letters, 
        //numbers and special characters) and no more than 2 equal characters in a row
        let regex = /^(?:(?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))(?!.*(.)\1{2,})[A-Za-z0-9!~<>,;:_=?*+#."&§%°()\|\[\]\-\$\^\@\/]{8,64}$/;

        return regex.test(pass) && !pass.toLowerCase().includes(username.toLowerCase()) &&
         !pass.toLowerCase().includes(email.toLowerCase().substring(0, email.indexOf("@")))},

    isValidEmail: input => {
        let regex = /^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$/;
        return regex.test(input)
    },
    isTeamTagValid: input => {
        let letterNumberRegex = /^[a-zA-Z0-9 .-]+$/;
        return input.length >= 2 && input.length <= 5 && input.match(letterNumberRegex);
    }
}
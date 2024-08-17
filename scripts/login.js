const input = {
    user: document.getElementById('user'),
    password: document.getElementById('pass')
}
function validarPass(pass) {
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(pass);
}




send.addEventListener('click',(e)=>{
    e.preventDefault()
    const newUsuario = {
        userName: input.user.value,
        password: input.password.value
    }
    if(validarPass(input.password.value) && input.user.value.length > 0){
        fetch('http://localhost:5000/users',{
            method: 'POST',
            headers:{
                'Content-Type': 'application/json',
            },
            body:JSON.stringify(newUsuario)
        })
        .then(res=>{
            if(res.status === 203){
                window.location.href = 'http://127.0.0.1:5500/public/index.html';
            }
        }).catch(err=>{
            input.password.style.border= "1px red solid";
                input.user.style.border= "1px red solid";
                setTimeout(()=>{
                    input.password.style.border= "none";
                    input.user.style.border= "none" ;
                },800)
        })
        
    }else{
        input.password.style.border= "1px red solid";
        input.user.style.border= "1px red solid";
                setTimeout(()=>{
                    input.password.style.border= "none";
                    input.user.style.border= "none" ;
                },800)
    }
})
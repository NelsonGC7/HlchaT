const input = {
    user: document.getElementById('inTex'),
    correo: document.getElementById('inCorreo'),
    password: document.getElementById('inPass')
}
const send  = document.getElementById('send');
const ya = document.getElementById('ya');

function validarEmail(email) {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}
function validarPass(pass) {
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(pass);
}
send.addEventListener('click',(e)=>{
    e.preventDefault()
    const newU ={
        userName: input.user.value,
        email: input.correo.value,
        password: input.password.value
    }
    console.log(send)
    if(validarEmail(input.correo.value) && validarPass(input.password.value)){
        fetch('http://localhost:5000/users/new',{
            method: 'POST',
            headers:{
                'content-type': 'application/json'
            },
            body: JSON.stringify(newU)
        }).then(res=> {
            res.status === 201 ? 
            window.location.href = 'http://127.0.0.1:5000/public/index.html' 
            : 
            console.log('error');
            res.status === 409 ? console.log('User already exist') : console.log('error');
            
        })
        
            .catch(err => console.log(err));
    }else{
        input.password.style.border= "1px red solid"
        input.correo.style.border= "1px red solid"
        setTimeout(()=>{
            input.password.style.border= "none"
            input.correo.style.border= "none" 
        },800)
    }
})
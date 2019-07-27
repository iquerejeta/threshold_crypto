//! In this example scenario, the "trusted key dealer" dissapears. We distribute the trust among
//! all actors. In a nutshell, such a scheme works by each of the actors acting as a trusted dealer
//! and finally combining all public keys into one. 
//! For this purpose we create the Teller (which is to be considered equivalent to actor. From now
//! on we will use 'teller').
//!
//! We follow the definition in 'Secure Distributed Key Generation for Discrete-Log Based Cryptosystems'
//! by Gennaro, Jarecki, Krawczyk and Rabin. We work uniquely in G_1 as this will give us higher 
//! computation speeds.
//! 
//! For the moment we assume that all tellers act honestly. Dealing with dishonest telles will come later.

use std::collections::BTreeMap;
use std::time::Instant;

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKeySet, PublicKeyShare, SecretKeySet,
    SecretKeyShare, G1,
};

#[derive(Clone, Debug)]
struct UntrustedSociety {
    actors: Vec<Actor>,
    pk_set: PublicKeySet,
}

impl UntrustedSociety {
    // Creates a new instance of UntrustedSociety by combining all actors and their respective public keys
    fn new(actors: Vec<Actor>, pk_sets: Vec<&PublicKeySet>) -> Self {
        let mut pk_set = pk_sets[0].clone();
        for i in 1..actors.len() {
            pk_set = pk_set.combine(pk_sets[i].clone());
        }
        UntrustedSociety { actors, pk_set }
    }
    
    fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors
            .get_mut(id)
            .expect("No `Actor` exists with that ID")
    }

    // Starts a new meeting of the secret society. Each time the set of actors receive an encrypted
    // message, at least 2 of them (i.e. 1 more than the threshold) must work together to decrypt
    // the ciphertext.
    fn start_decryption_meeting(&self) -> DecryptionMeeting {
        DecryptionMeeting {
            pk_set: self.pk_set.clone(),
            ciphertext: None,
            dec_shares: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct Teller {
    actors: Vec<PartialActor>,
    pk_set_1: PublicKeySet,
    pk_set_2: PublicKeySet,

}

impl Teller {
    // Creates a new instance of Teller. It generates two SecretKeySet, and shares the 
    // commitment of the polynomial, together with the secret shares of each of the other actors.
    fn new(n_actors: usize, threshold: usize) -> Self {
        let mut rng = rand::thread_rng();
        let sk_set_1 = SecretKeySet::random(threshold, &mut rng);
        let sk_set_2 = SecretKeySet::random(threshold, &mut rng);

        let pk_set_1 = sk_set_1.public_keys();
        let pk_set_2 = sk_set_2.public_keys();

        let combined_pk_sets = pk_set_1.combine(pk_set_2.clone());

        let actors = (0..n_actors)
            .map(|id| {
                let sk_share_1 = sk_set_1.secret_key_share(id);
                let sk_share_2 = sk_set_2.secret_key_share(id);
                
                PartialActor::new(id, sk_share_1, sk_share_2, combined_pk_sets.clone())
            })
            .collect();
        
        Teller {actors, pk_set_1, pk_set_2}
    }
}

// An actor, consisting of the fully computed secret shares
#[derive(Clone, Debug)]
struct Actor {
    id: usize, 
    sk_1: SecretKeyShare,
    sk_2: SecretKeyShare, // Don't really see why this is here
    pk_1: PublicKeyShare,
    com_sk_1: G1,
    msg_inbox: Option<Ciphertext>,
}

impl Actor{
    fn new(sk_shares: Vec<&PartialActor>, cheating_logs: &mut CheatingLogs) -> Actor {
        let mut sk_1 = sk_shares[0].sk_share_1.clone();
        let mut sk_2 = sk_shares[0].sk_share_2.clone();
        let id = sk_shares[0].id;
        let length = sk_shares.len() as usize;
        for i in 1..length {
            if id != sk_shares[i].id{
                panic!("id of all PartialActor must equal.")
            }
            if !sk_shares[i].check_commitment() {
                cheating_logs.cheating_events.push(i);
            }
            sk_1 = &sk_1 + &sk_shares[i].sk_share_1;
            sk_2 = &sk_2 + &sk_shares[i].sk_share_2;
        }
        let pk_1 = sk_1.public_key_share();
        let com_sk_1 = sk_1.commit();
        Actor {id, sk_1, sk_2, pk_1, com_sk_1, msg_inbox: None, }
    }
}

// A partial actor, consisting of the secret shares of a single teller. 
// It will contain both secret shares, together with a commitment
// of the polynomial which will allow the verification of the proceedure. The commitment must 
// be broadcasted, but we include it in the actor object to simplify the actors computations.
#[derive(Clone, Debug)]
struct PartialActor {
    id: usize,
    sk_share_1: SecretKeyShare,
    sk_share_2: SecretKeyShare,
    combined_pk_sets: PublicKeySet,
}

impl PartialActor {
    fn new(id: usize, sk_share_1: SecretKeyShare, sk_share_2: SecretKeyShare, combined_pk_sets: PublicKeySet) -> Self {
        PartialActor {
            id,
            sk_share_1,
            sk_share_2,
            combined_pk_sets,
        }
    }
    fn check_commitment(&self) -> bool {
        let pk_share_1 = self.sk_share_1.public_key_share();
        let pk_share_2 = self.sk_share_2.public_key_share();
        pk_share_1.combine(pk_share_2) == self.combined_pk_sets.public_key_share(self.id)
    }
}

// Sends an encrypted message to an `Actor`.
fn send_msg(actor: &mut Actor, enc_msg: Ciphertext) {
    actor.msg_inbox = Some(enc_msg);
}

// A meeting of the different actors. At this meeting, actors collaborate to decrypt a shared
// ciphertext.
struct DecryptionMeeting {
    pk_set: PublicKeySet,
    ciphertext: Option<Ciphertext>,
    dec_shares: BTreeMap<usize, DecryptionShare>,
}

impl DecryptionMeeting {
    // An actor contributes their decryption share to the decryption process.
    fn accept_decryption_share(&mut self, actor: &mut Actor) {
        let ciphertext = actor.msg_inbox.take().unwrap();

        // Check that the actor's ciphertext is the same ciphertext decrypted at the meeting.
        // The first actor to arrive at the decryption meeting sets the meeting's ciphertext.
        if let Some(ref meeting_ciphertext) = self.ciphertext {
            if ciphertext != *meeting_ciphertext {
                return;
            }
        } else {
            self.ciphertext = Some(ciphertext.clone());
        }

        let dec_share = actor.sk_1.decrypt_share(&ciphertext).unwrap();
        let dec_share_is_valid = actor
            .pk_1
            .verify_decryption_share(&dec_share, &ciphertext);
        assert!(dec_share_is_valid);
        self.dec_shares.insert(actor.id, dec_share);
    }

    // Tries to decrypt the shared ciphertext using the decryption shares.
    fn decrypt_message(&self) -> Result<Vec<u8>, ()> {
        let ciphertext = self.ciphertext.clone().unwrap();
        self.pk_set
            .decrypt(&self.dec_shares, &ciphertext)
            .map_err(|_| ())
    }
}

// The following structure will deal with the cheating parties
struct CheatingLogs{
    actors: Vec<usize>,
    cheating_events: Vec<usize>,
}

impl CheatingLogs {
    fn new(nr_actors: &usize) -> CheatingLogs {
        CheatingLogs{actors: (1..*nr_actors).map(|x| x).collect(), cheating_events: Vec::new()}
    }
}

fn main() {
    // We will give an example were we have three trustees, where the treshold is one (this is, at least two entities must collaborate). 
    // Hence, we initiate three tellers.
    let nmbr_users = 50;
    let nmbr_users_128 = nmbr_users.clone() as u128;
    let threshold = 40;
    let mut tellers: Vec<Teller> = Vec::new();
    let mut master_pk_set: Vec<&PublicKeySet> = Vec::new();
    let mut now = Instant::now();
    for _ in 0..nmbr_users {
        let tmp_teller = Teller::new(nmbr_users, threshold);
        tellers.push(tmp_teller.clone());
    }
    let time_gen_teller = now.elapsed().as_millis() / &nmbr_users_128;
    // Initiate the cheating logs
    let mut cheating_logs = CheatingLogs::new(&nmbr_users);
    // Now we need to initiate the different Actors. This is done by using each of the partial actors generated by the tellers. 
    now = Instant::now();
    let mut actors: Vec<Actor> = Vec::new();
        for i in 0..nmbr_users {
        let mut partial_actors: Vec<&PartialActor> = Vec::new();
        for j in 0..nmbr_users {
            partial_actors.push(&tellers[j].actors[i]);
        }
        master_pk_set.push(&tellers[i].pk_set_1);
        actors.push(
            Actor::new(partial_actors, &mut cheating_logs)
        )
    }
    let time_gen_actors = now.elapsed().as_millis() / &nmbr_users_128;
    // We are assuming for the moment that each of the tellers is honest

    now = Instant::now();
    let mut society = UntrustedSociety::new(actors, master_pk_set);
    let time_gen_society = now.elapsed().as_millis() / &nmbr_users_128;
    // Hence we generate the public key without the second check
    let master_pub_key = society.clone().pk_set;

    // We encrypt the plaintext
    let msg = b"let's get pizza";
    let ciphertext = master_pub_key.public_key().encrypt(msg);

    // We send the messages to each of the actors
    for i in 0..nmbr_users {
        send_msg(&mut society.actors[i], ciphertext.clone());
    }

    // We begin the decryption process
    let mut meeting = society.start_decryption_meeting();

    // Until we get the threshold + 1 players decrypting, we will get an error
    now = Instant::now();
    for i in 0..threshold {
        meeting.accept_decryption_share(society.get_actor(i));
        assert!(meeting.decrypt_message().is_err());
    }
    // Then, we will get successful decryptions
    for i in 0..(nmbr_users - threshold) {
        meeting.accept_decryption_share(society.get_actor(threshold + i));
        let res = meeting.decrypt_message();
        assert!(res.is_ok());
        assert_eq!(msg, res.unwrap().as_slice());
    }
    let time_decryption = now.elapsed().as_millis() / &nmbr_users_128;

    println!("+----------------------------------------------------------------------+");
    println!("| Printing times for {} parties with a threshold of {} in miliseconds. |", nmbr_users, threshold);
    println!("+----------------------------------------------------------------------+");
    println!("Generate a teller: {}", time_gen_teller);
    println!("Generate an actor: {}", time_gen_actors);
    println!("Initiate the untrusted society: {}", time_gen_society);
    println!("Decrypting ciphertext by all parties: {}", time_decryption);
}
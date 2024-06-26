const db = require("../db");
const {TampilAdminId} =require("../control/page")

const RiwayatUser = (req,res) => {
    const username = req.params.username
    const isikueri = `SELECT * FROM siswa WHERE username = '${username}'`

    db.query( isikueri, (err, results) => {
        if(err){
            throw err;
        } else {
            res.set('Access-Control-Allow-Origin', '*')

            const queryHistoryUser = `SELECT kode_transaksi, buku.kode_buku, buku.judul_buku, buku.pengarang, buku.penerbit, buku.tahun_terbit, siswa.no_induk, siswa.nama, jumlah_pinjam, pengembalian.jumlah_kembali, tanggal_pinjam, peminjam_buku.tanggal_kembali, status_pinjam FROM peminjam_buku 
            LEFT JOIN buku ON peminjam_buku.id_buku = buku.id 
            LEFT JOIN siswa ON peminjam_buku.id_siswa = siswa.id
            LEFT JOIN pengembalian ON peminjam_buku.id = pengembalian.id_transaksi
            WHERE siswa.nama = "${results[0].nama}"
            ORDER BY tanggal_pinjam DESC`
        
            db.query(queryHistoryUser,(err, results) => {
                if(err){
                    throw err;
                } else {
                    res.set('Access-Control-Allow-Origin', '*')
                    res.send(results)
                }
            })
        }
    });

}

const NotifUser = (req,res)=>{
    const username = req.params.username
    const query =  `SELECT mesage_user FROM notifications 
    LEFT JOIN peminjam_buku ON notifications.kode_transaksi = peminjam_buku.kode_transaksi 
    LEFT JOIN siswa ON peminjam_buku.id_siswa = siswa.id WHERE siswa.no_induk = "${username}"  AND notifications.read_status_user = 0
    ORDER BY notifications.kode_transaksi DESC`
    db.query(query, (err,result)=>{
    if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }else{
        res.set('Access-Control-Allow-Origin', '*')
        res.status(200).send(result)
    }
    })
}


module.exports = {RiwayatUser,NotifUser}

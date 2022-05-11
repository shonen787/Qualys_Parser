
use std::fs::File;
use xml::{EventReader, EventWriter};
use xml::reader::XmlEvent;
use get_size::GetSize;
use std::io::{BufRead,BufReader};
use odbc::*;
use odbc_safe::AutocommitOn;
use colored::Colorize;




#[derive(GetSize)]
#[derive(Debug)]
struct Vulnerabilities{
    VulnerabilityName: Vec<String>,
    IpAddress: String,
    HostName: String,
    Category: Vec<String>,
    SecurityLevel: Vec<i8>,
    Explanation: Vec<String>,
    Solution: Vec<String>,
    IndustryReference: Vec<String>,
    Result: Vec<String>,
    Ports: Ports,
}


#[derive(GetSize)]
#[derive(Debug)]
struct Ports{
    IpAddress: Vec<String>,
    Type: Vec<String>,
    Port: Vec<String>,
    Description: Vec<String>,
}

fn get_files() -> Vec<std::path::PathBuf>{
    let mut faxvec: Vec<std::path::PathBuf> = Vec::new();
    for element in std::path::Path::new("").read_dir().unwrap() {
        let path = element.unwrap().path();
        if let Some(extension) = path.extension() {
            if extension == "xml" {
                faxvec.push(path);
            }
        }
    }
    faxvec
}

fn build_vector()-> Vec<Vulnerabilities>{
    let xmlvec: Vec<std::path::PathBuf> = get_files();
    let mut vulnvec: Vec<Vulnerabilities> = Vec::new();
    
    let mut vulnname: Vec<String> = Vec::new();
    let mut vulnip: String = String::from("");
    let mut vulnhost: String = String::from("");
    let mut vulncat: Vec<String> = Vec::new();
    let mut vulnsec: Vec<i8> = Vec::new();
    let mut vulnex: Vec<String> = Vec::new();
    let mut vulnsol: Vec<String> = Vec::new();
    let mut vulnind: Vec<String> = Vec::new();
    let mut vulnre: Vec<String> = Vec::new();

    let mut portsip: Vec<String> = Vec::new();
    let mut portstype: Vec<String> = Vec::new();
    let mut portsport: Vec<String> = Vec::new();
    let mut portsdes: Vec<String> = Vec::new();

    let mut isittitle: bool = false;
    let mut isitex: bool = false;
    let mut issol: bool = false;
    let mut isres: bool = false;
    let mut isind: bool = false;
    let mut push : bool = false;
    let mut portguardtcp: bool = false;
    let mut portguardudp: bool = false;

    for file in xmlvec{
        let openfile= File::open(file).unwrap();
        let openfile = EventReader::new(BufReader::new(openfile));

        for e in openfile{
            match e {
                Ok(XmlEvent::StartElement { name, attributes, ..})=>{
                    if name.local_name == "IP" {
                        for x in &attributes {
                            if x.name.to_string().contains("value")  {  vulnip = x.value.clone();};
                            if x.name.to_string().contains("name")  {  vulnhost = x.value.clone();};}}

                    if name.local_name == "CAT"{
                        for x in &attributes{
                            if x.name.to_string().contains("value") { 
                                vulncat.push(x.value.clone());}
                            //println!("{}", x.value)
                        }
                    }

                    if name.local_name =="INFO"{
                        for x in &attributes{
                            if x.name.to_string().contains("severity")  { vulnsec.push(x.value.clone().parse::<i8>().unwrap())};
                        }   }
                    if name.local_name == "TITLE"{
                        isittitle = true;

                        }
                    
                    if name.local_name == "DIAGNOSIS"{
                        isitex=true;}
                    if name.local_name == "SOLUTION"{
                        issol=true;}
                    if name.local_name == "RESULT"{
                        isres=true;}
                    if name.local_name == "ID" || name.local_name == "URL"{
                        isind=true;}

                }

                Ok(XmlEvent::CData(text))=>{
                    if isittitle{
                        if text =="Open TCP Services List"{portguardtcp = true;}
                        if text =="Open UDP Services List"{portguardudp = true;}
                        vulnname.push(text.clone());
                        //println!(" {}", text);
                        isittitle = false;}
                    if isitex{
                       vulnex.push(text.clone());
                        //println!("{}", text);
                        isitex = false;}
                    if issol{
                        vulnsol.push(text.clone());
                        //println!("{}", text);
                        issol = false;}
                    if isres{
                        if portguardtcp {
                                let mut guard = false;
                                for s in text.lines()
                                {
                                    let mut i =0;
                                    if guard{
                                        for a in s.split_terminator("\t"){
                                            if i ==0{
                                                portsport.push(a.to_string());
                                            }
                                            if i ==1{
                                                portstype.push(String::from("TCP"));
                                            }
                                            if i ==2{
                                                portsip.push(vulnip.clone());
                                            }
                                            if i ==3{
                                                portsdes.push(a.to_string());
       
                                            }

                                            i +=1;
                                            }
                                            
                                        continue;
                                    }else{guard = true}
                                }                            
                           //println!("{}",text);
                           
                           portguardtcp=false;
                        } else if portguardudp{
                            let mut guard = false;
                                for s in text.lines()
                                {
                                    let mut i =0;
                                    if guard{
                                        for a in s.split_terminator("\t"){
                                            if i ==0{
                                                portsport.push(a.to_string());
                                            }
                                            if i ==1{
                                                portstype.push(String::from("UDP"));
                                            }
                                            if i ==2{
                                                portsip.push(vulnip.clone());
                                            }
                                            if i ==3{
                                                portsdes.push(a.to_string());
       
                                            }
                                            i +=1;
                                            }
                                        continue;
                                    }else{guard = true}
                                }                            
                           //println!("{}",text);
                           portguardudp=false;

                        }
                        else{
                        vulnre.push(text.clone());
                        //println!(" {}", text);
                    }
                        isres = false;
                    }
                    if isind{
                        vulnind.push(text.clone());
                        //println!(" {}", text);
                        isind = false;}
                 
                   
                }
                Ok(XmlEvent::EndElement{name})=>{
                    if name.local_name == "IP"{
                        push = true;
                       // println!("Finishied with: {} - {}", vulnip, vulnhost);
                    }
                    
                }
                Err(e) => { 
                    println!("Error: {}", e);
                    break;
                }
                _ =>{}
            }
            if push{ 
               vulnvec.push(Vulnerabilities{VulnerabilityName: vulnname.clone(),
                IpAddress: vulnip.clone(),
                HostName: vulnhost.clone(),
                Category: vulncat.clone(),
                SecurityLevel: vulnsec.clone(),
                Explanation: vulnex.clone(),
                Solution: vulnsol.clone(),
                IndustryReference: vulnind.clone(),
                Result: vulnre.clone(),
                Ports: Ports{
                    IpAddress: portsip.clone(),
                    Type: portstype.clone(),
                    Port: portsport.clone(),
                    Description: portsdes.clone(),},
                }
            );
                
            vulnname.clear();
            vulnip.clear();
            vulnhost.clear();
            vulncat.clear();
            vulnsec.clear();
            vulnex.clear();
            vulnsol.clear();
            vulnind.clear();
            vulnre.clear();
            portsip.clear();
            portstype.clear();
            portsport.clear();
            portsdes.clear();
            push =false;
            }
        }
    }
    vulnvec
}

fn clean(f: String) -> std::result::Result<(), DiagnosticRecord> {

    let env = create_environment_v3().map_err(|e| e.unwrap())?;

    let mut buffer = String::from("DRIVER={MICROSOFT ACCESS DRIVER (*.mdb, *.accdb)};
    DBQ=./qualys.mdb");
    let conn = env.connect_with_connection_string(&buffer)?;
    execute_statement_clean(&conn,f)

}

fn execute_statement_clean<'env>(conn: &Connection<'env, AutocommitOn>,f: String) -> Result<()> {
    let stmt = Statement::with_parent(conn)?;
    // println!("Please enter SQL statement string: ");
    // io::stdin().read_line(&mut sql_text).unwrap();
    //println!("{}", &*f);
    match stmt.exec_direct(&f.to_string())? {
        Data(mut stmt) => {

            let cols = stmt.num_result_cols()?;
            while let Some(mut cursor) = stmt.fetch()? {
                for i in 1..(cols + 1) {
                    match cursor.get_data::<&str>(i as u16)? {
                        Some(val) => print!(" {}", val),
                        None => print!(" NULL"),
                    }
                }
                println!("");
            }
        }
        NoData(_) => println!(""),
    }

    Ok(())
}

fn connect(vulnvec: Vec<Vulnerabilities>) -> std::result::Result<(), DiagnosticRecord> {

    let env = create_environment_v3().map_err(|e| e.unwrap())?;

    let buffer = String::from("DRIVER={MICROSOFT ACCESS DRIVER (*.mdb, *.accdb)};
    DBQ=./qualys.mdb");
    let conn = env.connect_with_connection_string(&buffer)?;
    execute_statement(&conn,vulnvec)

}

fn execute_statement<'env>(conn: &Connection<'env, AutocommitOn>,vulnvec: Vec<Vulnerabilities>) -> Result<()> {
    use sprintf::sprintf;
    for item in vulnvec.iter(){

        let mut n = 0;
        let mut query = String::from("");
        let ipaddress = item.IpAddress.clone();
      //  println!("⚠️ ");
        println!("Working on {}", ipaddress);
        //println!(" ⚠️");
        while &n < &item.VulnerabilityName.len()
        {
            if (&item.VulnerabilityName[n].to_string() != "Open TCP Services List" ||
             &item.VulnerabilityName[n].to_string() !="Open UDP Services List"|| 
             &item.VulnerabilityName[n].to_string() !="Traceroute" ||
             &item.VulnerabilityName[n].to_string() !="DNS Host Name")
            {
                let stmt = Statement::with_parent(conn)?;
                query = sprintf!("Insert into Qualys_Vul Values ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')",
                ipaddress.to_string(),
                item.VulnerabilityName[n].to_string(),
                item.Category[n].to_string(),
                item.SecurityLevel[n].to_string(),
                item.Explanation[n].to_string(),
                item.Solution[n].to_string(),
                "",
                item.Result[n].to_string(),
                "",
                ""
                ).unwrap();
                stmt.exec_direct(&query.to_string());
                // match stmt.exec_direct(&query.to_string())? {
                //         Data(mut stmt) => {       

                //             let cols = stmt.num_result_cols()?;
                //             while let Some(mut cursor) = stmt.fetch()? {
                //                 for i in 1..(cols + 1) {
                //                     match cursor.get_data::<&str>(i as u16)? {
                //                         Some(val) => print!(" {}", val),
                //                         None => print!(" NULL"),
                //                     }
                //                 }
                //                 println!("Added in {} ", item.Ports.IpAddress[n]);
                //             }
                //         }
                //         NoData(_) => print!("No Data Added"),
                //     }
            }else{
                println!("Hit a skip")
            }
            n+=1;

        }

       let mut n = 0;
        let mut query = String::from("");
        while &n < &item.Ports.Port.len() {
            let stmt = Statement::with_parent(conn)?;
            query = sprintf!("Insert into Ports Values ('%s','%s','%s','%s')",item.Ports.IpAddress[n].to_string(),item.Ports.Type[n].to_string(),item.Ports.Port[n].to_string(),item.Ports.Description[n].to_string()).unwrap();
            stmt.exec_direct(&query.to_string());
            // match stmt.exec_direct(&query.to_string())? {
            //     Data(mut stmt) => {
    
            //         let cols = stmt.num_result_cols()?;
            //         while let Some(mut cursor) = stmt.fetch()? {
            //             for i in 1..(cols + 1) {
            //                 match cursor.get_data::<&str>(i as u16)? {
            //                     Some(val) => print!(" {}", val),
            //                     None => print!(" NULL"),
            //                 }
            //             }
            //             println!("Added in {} ", item.Ports.IpAddress[n]);
            //         }
            //     }
            //     NoData(_) => print!(""),
            // }
            n+=1;
        }

        println!("Finished!");
        //print!("\x1B[2J\x1B[1;1H");    

    }

    Ok(())
}

fn main() { 
    
    println!("{}",format!("Going to inport into Qualys DB.").bold().blue());

    let mut vulnvec: Vec<Vulnerabilities>;

    //Clear DB    
    match clean(String::from("Delete from Ports")) {
        Ok(()) => println!("{} {} {}","☣️",format!("Clearning out Ports.").bold().blue(),"☣️"),
        Err(diag) => println!("Error: {}", diag),
    }
    match clean(String::from("Delete from Qualys_Vul")) {
        Ok(()) => println!("{} {} {}","☣️",format!("Clearning out Qualys_Vul.").bold().blue(),"☣️"),
        Err(diag) => println!("Error: {}", diag),
    }
    
    vulnvec = build_vector();

    for i in &mut vulnvec{
          while i.Category.len() < i.VulnerabilityName.len(){
            i.Category.push(String::from(""));
        }
        while i.IndustryReference.len() < i.VulnerabilityName.len(){
            i.IndustryReference.push(String::from(""));
        }       
        while i.SecurityLevel.len() < i.VulnerabilityName.len(){
            i.SecurityLevel.push(1);
        }
        while i.Solution.len() < i.VulnerabilityName.len(){
            i.Solution.push(String::from(""));
        }
        while i.Result.len() < i.VulnerabilityName.len(){
            i.Result.push(String::from(""));
        }
        // println!("IP address: {}", i.IpAddress);
        // println!("Hostname: {}", i.HostName);
        // println!("Size of Vulnerabilities: {:?}", i.VulnerabilityName.len());
        //println!("Size of Category : {:?}", i.Category);
        // println!("Size of Industry Reference: {:?}", i.IndustryReference.len());
        // println!("Size of Security Level: {:?}", i.SecurityLevel.len());
        // println!("Size of explanation: {:?}", i.Explanation.len());
        // println!("Size of Solution: {:?}", i.Solution.len());
        // println!("Size of Result: {:?}", i.Result.len());
        // println!("");
    }



   connect(vulnvec);

   println!("{}", format!("All Done").bold().green().underline());
 
}





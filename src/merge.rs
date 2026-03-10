use std::error::Error;
use std::path::Path;

use rayon::prelude::*;

pub trait Merge: Sized {
    fn merge_in_place(&mut self, other: &Self);

    fn merge(mut self, other: Self) -> Self {
        self.merge_in_place(&other);
        self
    }
}

pub trait PostcardIO: Sized + serde::Serialize + serde::de::DeserializeOwned {
    fn from_file(path: &Path) -> Result<Self, Box<dyn Error>> {
        let bytes = std::fs::read(path)?;
        Ok(postcard::from_bytes(&bytes)?)
    }

    fn write(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let bytes = postcard::to_stdvec(self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

pub fn merge_from_directory<T>(path: &std::path::Path) -> Result<T, Box<dyn Error>>
where
    T: std::fmt::Debug + Merge + PostcardIO + Send + Sync,
{
    let items: Vec<T> = std::fs::read_dir(path)?
        .map(|entry| {
            let entry = entry?;
            T::from_file(&entry.path())
        })
        .collect::<Result<_, _>>()?;

    items
        .into_par_iter()
        .reduce_with(|a, b| a.merge(b))
        .ok_or("Directory is empty".into())
}

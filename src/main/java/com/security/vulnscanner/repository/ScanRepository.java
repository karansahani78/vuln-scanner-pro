package com.security.vulnscanner.repository;

import com.security.vulnscanner.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findByTargetId(Long targetId);
    List<Scan> findByStatus(Scan.ScanStatus status);
    
    @Query("SELECT s FROM Scan s WHERE s.target.user.id = :userId ORDER BY s.createdAt DESC")
    List<Scan> findByUserId(Long userId);
    
    @Query("SELECT s FROM Scan s WHERE s.target.id = :targetId ORDER BY s.createdAt DESC")
    List<Scan> findByTargetIdOrderByCreatedAtDesc(Long targetId);
    
    // For preventing concurrent scans on same target
    long countByTargetIdAndStatus(Long targetId, Scan.ScanStatus status);
}
